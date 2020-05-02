import socket
from concurrent.futures._base import Future
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from nassl._nassl import OpenSSLError
from nassl.legacy_ssl_client import LegacySslClient

from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandExtraArguments,
    ScanJob,
    ScanCommandResult,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


@dataclass(frozen=True)
class SessionRenegotiationScanResult(ScanCommandResult):
    """The result of testing a server for insecure TLS renegotiation and client-initiated renegotiation.

    Attributes:
        accepts_client_renegotiation: True if the server honors client-initiated renegotiation attempts.
        supports_secure_renegotiation: True if the server supports secure renegotiation.
    """

    accepts_client_renegotiation: bool
    supports_secure_renegotiation: bool


class _ScanJobResultEnum(Enum):
    ACCEPTS_CLIENT_RENEG = 1
    SUPPORTS_SECURE_RENEG = 2


class _SessionRenegotiationCliConnector(ScanCommandCliConnector[SessionRenegotiationScanResult, None]):

    _cli_option = "reneg"
    _cli_description = "Test a server for for insecure TLS renegotiation and client-initiated renegotiation."

    @classmethod
    def result_to_console_output(cls, result: SessionRenegotiationScanResult) -> List[str]:
        result_txt = [cls._format_title("Session Renegotiation")]

        # Client-initiated reneg
        client_reneg_txt = (
            "VULNERABLE - Server honors client-initiated renegotiations"
            if result.accepts_client_renegotiation
            else "OK - Rejected"
        )
        result_txt.append(cls._format_field("Client-initiated Renegotiation:", client_reneg_txt))

        # Secure reneg
        secure_txt = (
            "OK - Supported"
            if result.supports_secure_renegotiation
            else "VULNERABLE - Secure renegotiation not supported"
        )
        result_txt.append(cls._format_field("Secure Renegotiation:", secure_txt))

        return result_txt


class SessionRenegotiationImplementation(ScanCommandImplementation[SessionRenegotiationScanResult, None]):
    """Test a server for insecure TLS renegotiation and client-initiated renegotiation.
    """

    cli_connector_cls = _SessionRenegotiationCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no reneg with TLS 1.3
        if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
            tls_version_to_use = TlsVersionEnum.TLS_1_2
        else:
            tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported

        return [
            ScanJob(function_to_call=_test_secure_renegotiation, function_arguments=[server_info, tls_version_to_use]),
            ScanJob(function_to_call=_test_client_renegotiation, function_arguments=[server_info, tls_version_to_use]),
        ]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> SessionRenegotiationScanResult:
        if len(completed_scan_jobs) != 2:
            raise RuntimeError(f"Unexpected number of scan jobs received: {completed_scan_jobs}")

        results_dict = {}
        for job in completed_scan_jobs:
            result_enum, value = job.result()
            results_dict[result_enum] = value

        return SessionRenegotiationScanResult(
            accepts_client_renegotiation=results_dict[_ScanJobResultEnum.ACCEPTS_CLIENT_RENEG],
            supports_secure_renegotiation=results_dict[_ScanJobResultEnum.SUPPORTS_SECURE_RENEG],
        )


def _test_secure_renegotiation(
    server_info: ServerConnectivityInfo, tls_version_to_use: TlsVersionEnum
) -> Tuple[_ScanJobResultEnum, bool]:
    """Check whether the server supports secure renegotiation.
    """
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version_to_use, should_use_legacy_openssl=True
    )
    if not isinstance(ssl_connection.ssl_client, LegacySslClient):
        raise RuntimeError("Should never happen")

    try:
        # Perform the SSL handshake
        ssl_connection.connect()
        supports_secure_renegotiation = ssl_connection.ssl_client.get_secure_renegotiation_support()

    finally:
        ssl_connection.close()

    return _ScanJobResultEnum.SUPPORTS_SECURE_RENEG, supports_secure_renegotiation


def _test_client_renegotiation(
    server_info: ServerConnectivityInfo, tls_version_to_use: TlsVersionEnum
) -> Tuple[_ScanJobResultEnum, bool]:
    """Check whether the server honors session renegotiation requests.
    """
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version_to_use, should_use_legacy_openssl=True
    )
    if not isinstance(ssl_connection.ssl_client, LegacySslClient):
        raise RuntimeError("Should never happen")

    try:
        # Perform the SSL handshake
        ssl_connection.connect()

        try:
            # Let's try to renegotiate
            ssl_connection.ssl_client.do_renegotiate()
            accepts_client_renegotiation = True

        # Errors caused by a server rejecting the renegotiation
        except socket.timeout:
            # This is how Netty rejects a renegotiation - https://github.com/nabla-c0d3/sslyze/issues/114
            accepts_client_renegotiation = False
        except ConnectionError:
            accepts_client_renegotiation = False
        except OSError as e:
            # OSError is the parent of all (non-TLS) socket/connection errors so it should be last
            if "Nassl SSL handshake failed" in e.args[0]:
                # Special error returned by nassl
                accepts_client_renegotiation = False
            else:
                raise
        except OpenSSLError as e:
            if "handshake failure" in e.args[0]:
                accepts_client_renegotiation = False
            elif "no renegotiation" in e.args[0]:
                accepts_client_renegotiation = False
            elif "tlsv1 unrecognized name" in e.args[0]:
                # Yahoo's very own way of rejecting a renegotiation
                accepts_client_renegotiation = False
            elif "tlsv1 alert internal error" in e.args[0]:
                # Jetty server: https://github.com/nabla-c0d3/sslyze/issues/290
                accepts_client_renegotiation = False
            elif "decryption failed or bad record mac" in e.args[0]:
                # Some servers such as reddit.com
                accepts_client_renegotiation = False
            elif "sslv3 alert unexpected message" in e.args[0]:
                # traefik https://github.com/nabla-c0d3/sslyze/issues/422
                accepts_client_renegotiation = False

            else:
                raise

    finally:
        ssl_connection.close()

    return _ScanJobResultEnum.ACCEPTS_CLIENT_RENEG, accepts_client_renegotiation
