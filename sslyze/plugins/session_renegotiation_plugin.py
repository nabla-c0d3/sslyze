import socket
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

import pydantic
from nassl._nassl import OpenSSLError
from nassl.legacy_ssl_client import LegacySslClient

from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.errors import ServerRejectedTlsHandshake
from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandExtraArgument,
    ScanJob,
    ScanCommandResult,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
    ScanJobResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


@dataclass(frozen=True)
class SessionRenegotiationScanResult(ScanCommandResult):
    """The result of testing a server for insecure TLS renegotiation and client-initiated renegotiation.

    Attributes:
        accepts_client_renegotiation: True if the server honors client-initiated renegotiation attempts.
        supports_secure_renegotiation: True if the server supports secure renegotiation.
    """

    supports_secure_renegotiation: bool
    is_vulnerable_to_client_renegotiation_dos: bool


# Identical fields in the JSON output
SessionRenegotiationScanResultAsJson = pydantic.dataclasses.dataclass(SessionRenegotiationScanResult, frozen=True)


class SessionRenegotiationScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[SessionRenegotiationScanResultAsJson]  # type: ignore


class _ScanJobResultEnum(Enum):
    IS_VULNERABLE_TO_CLIENT_RENEG_DOS = 1
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
            if result.is_vulnerable_to_client_renegotiation_dos
            else "OK - Not vulnerable"
        )
        result_txt.append(cls._format_field("Client Renegotiation DoS Attack:", client_reneg_txt))

        # Secure reneg
        secure_txt = (
            "OK - Supported"
            if result.supports_secure_renegotiation
            else "VULNERABLE - Secure renegotiation not supported"
        )
        result_txt.append(cls._format_field("Secure Renegotiation:", secure_txt))

        return result_txt


class SessionRenegotiationImplementation(ScanCommandImplementation[SessionRenegotiationScanResult, None]):
    """Test a server for insecure TLS renegotiation and client-initiated renegotiation."""

    cli_connector_cls = _SessionRenegotiationCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [
            ScanJob(function_to_call=_test_secure_renegotiation, function_arguments=[server_info]),
            ScanJob(function_to_call=_test_client_renegotiation, function_arguments=[server_info]),
        ]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> SessionRenegotiationScanResult:
        if len(scan_job_results) != 2:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        results_dict = {}
        for job in scan_job_results:
            result_enum, value = job.get_result()
            results_dict[result_enum] = value

        return SessionRenegotiationScanResult(
            is_vulnerable_to_client_renegotiation_dos=results_dict[
                _ScanJobResultEnum.IS_VULNERABLE_TO_CLIENT_RENEG_DOS
            ],
            supports_secure_renegotiation=results_dict[_ScanJobResultEnum.SUPPORTS_SECURE_RENEG],
        )


def _test_secure_renegotiation(server_info: ServerConnectivityInfo) -> Tuple[_ScanJobResultEnum, bool]:
    """Check whether the server supports secure renegotiation."""
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no reneg with TLS 1.3
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        tls_version_to_use = TlsVersionEnum.TLS_1_2
        downgraded_from_tls_1_3 = True
    else:
        tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported
        downgraded_from_tls_1_3 = False

    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version_to_use,
        should_use_legacy_openssl=True,  # Only the legacy SSL client has methods to check for secure reneg
    )
    if not isinstance(ssl_connection.ssl_client, LegacySslClient):
        raise RuntimeError("Should never happen")

    try:
        # Perform the TLS handshake
        ssl_connection.connect()
        supports_secure_renegotiation = ssl_connection.ssl_client.get_secure_renegotiation_support()

    # Should only happen when the server only supports TLS 1.3
    except ServerRejectedTlsHandshake:
        if downgraded_from_tls_1_3:
            supports_secure_renegotiation = True  # Technically TLS 1.3 has no renegotiation therefore it is secure
        else:
            raise

    finally:
        ssl_connection.close()

    return _ScanJobResultEnum.SUPPORTS_SECURE_RENEG, supports_secure_renegotiation


def _test_client_renegotiation(server_info: ServerConnectivityInfo) -> Tuple[_ScanJobResultEnum, bool]:
    """Check whether the server honors session renegotiation requests."""
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no reneg with TLS 1.3
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        tls_version_to_use = TlsVersionEnum.TLS_1_2
        downgraded_from_tls_1_3 = True
    else:
        tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported
        downgraded_from_tls_1_3 = False

    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version_to_use,
        should_use_legacy_openssl=True,  # Only the legacy SSL client has methods to trigger a reneg
    )
    if not isinstance(ssl_connection.ssl_client, LegacySslClient):
        raise RuntimeError("Should never happen")

    try:
        # Perform the TLS handshake
        ssl_connection.connect()

    # Should only happen when the server only supports TLS 1.3
    except ServerRejectedTlsHandshake:
        if downgraded_from_tls_1_3:
            accepts_client_renegotiation = False  # Technically TLS 1.3 has no renegotiation therefore it is secure
        else:
            raise

    # The initial TLS handshake went well; let's try to do a renegotiation
    else:
        try:
            # Do a reneg multiple times in a row to be 100% sure that the server has no mitigations in place
            # https://github.com/nabla-c0d3/sslyze/issues/473
            for i in range(10):
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
            elif "shut down by peer" in e.args[0]:
                # Cloudfront
                accepts_client_renegotiation = False
            elif "unexpected record" in e.args[0]:
                # Indy TCP Server with special RSA Token authentication https://github.com/nabla-c0d3/sslyze/issues/483
                accepts_client_renegotiation = False
            elif "wrong version number" in e.args[0]:
                # Seen with exim 4.92-5 + gnutls 3.7.1
                accepts_client_renegotiation = False

            else:
                raise

    finally:
        ssl_connection.close()

    return _ScanJobResultEnum.IS_VULNERABLE_TO_CLIENT_RENEG_DOS, accepts_client_renegotiation
