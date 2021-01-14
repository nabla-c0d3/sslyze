import socket
from concurrent.futures._base import Future
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

from nassl._nassl import OpenSSLError
from nassl.legacy_ssl_client import LegacySslClient

from sslyze.plugins.plugin_base import (
    OptParseCliOption,
    ScanCommandImplementation,
    ScanCommandExtraArguments,
    ScanJob,
    ScanCommandResult,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum

@dataclass(frozen=True)
class SessionRenegotiationExtraArguments(ScanCommandExtraArguments):
    """Additional configuration for running the RENEG scan command.

    Attributes:
        cir: Maximum amount of attempts for client-initiated renegotiation.
    """

    cir: int

@dataclass(frozen=True)
class SessionRenegotiationScanResult(ScanCommandResult):
    """The result of testing a server for insecure TLS renegotiation and client-initiated renegotiation.

    Attributes:
        accepts_client_renegotiation: True if the server honors client-initiated renegotiation attempts.
        supports_secure_renegotiation: True if the server supports secure renegotiation.
    """

    accepts_client_renegotiation: int
    supports_secure_renegotiation: bool


class _ScanJobResultEnum(Enum):
    ACCEPTS_CLIENT_RENEG = 1
    SUPPORTS_SECURE_RENEG = 2


class _SessionRenegotiationCliConnector(ScanCommandCliConnector[SessionRenegotiationScanResult, SessionRenegotiationExtraArguments]):

    _cli_option = "reneg"
    _cli_description = "Test a server for for insecure TLS renegotiation and client-initiated renegotiation."

    @classmethod
    def get_cli_options(cls) -> List[OptParseCliOption]:
        scan_command_option = super().get_cli_options()
        scan_command_option.append(
            OptParseCliOption(
                option="cir",
                help="Amount of client-initiated renegotiation attempts. Must be used with --reneg",
                action="store",
            )
        )
        return scan_command_option

    @classmethod
    def find_cli_options_in_command_line(
        cls, parsed_command_line: Dict[str, Union[None, bool, str]]
    ) -> Tuple[bool, Optional["SessionRenegotiationExtraArguments"]]:

        # check if --reneg was used - currently not relevant
        is_scan_cmd_enabled, _ = super().find_cli_options_in_command_line(parsed_command_line)

        # check if --cir was used
        extra_arguments = None
        try:
            cir = parsed_command_line["cir"]
            if cir:
                cir = int(cir)
                if not is_scan_cmd_enabled:
                    raise ScanCommandWrongUsageError(f"Option --cir cannot be used without --reneg (or --regular)!")
                #if not isinstance(cir, int):
                #    raise TypeError(f"Expected an int for cir but received {cir}")
                extra_arguments = SessionRenegotiationExtraArguments(cir)
        except KeyError:
            pass

        return is_scan_cmd_enabled, extra_arguments

    @classmethod
    def result_to_console_output(cls, result: SessionRenegotiationScanResult) -> List[str]:
        result_txt = [cls._format_title("Session Renegotiation")]

        # Client-initiated reneg
        if result.accepts_client_renegotiation > 0:
            client_reneg_txt = "VULNERABLE - Worked " + str(result.accepts_client_renegotiation) + " times!"
        else:
            client_reneg_txt = "OK - Rejected"
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
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[SessionRenegotiationExtraArguments] = None
    ) -> List[ScanJob]:
        cir = str(extra_arguments.cir) if extra_arguments else 1
        # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no reneg with TLS 1.3
        if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
            tls_version_to_use = TlsVersionEnum.TLS_1_2
        else:
            tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported

        return [
            ScanJob(function_to_call=_test_secure_renegotiation, function_arguments=[server_info, tls_version_to_use]),
            ScanJob(function_to_call=_test_client_renegotiation, function_arguments=[server_info, tls_version_to_use, cir]),
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
    server_info: ServerConnectivityInfo, tls_version_to_use: TlsVersionEnum, cir: int
) -> Tuple[_ScanJobResultEnum, int]:
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
        i = 0
        try:
            # Let's try to renegotiate
            for i in range(int(cir)):
                ssl_connection.ssl_client.do_renegotiate()
                accepts_client_renegotiation = i + 1 # Python ranges, there is no 0th attempt

        #Errors caused by a server rejecting the renegotiation
        except socket.timeout:
            # This is how Netty rejects a renegotiation - https://github.com/nabla-c0d3/sslyze/issues/114
            accepts_client_renegotiation = i
        except ConnectionError:
            accepts_client_renegotiation = i
        except OSError as e:
            # OSError is the parent of all (non-TLS) socket/connection errors so it should be last
            if "Nassl SSL handshake failed" in e.args[0]:
                # Special error returned by nassl
                accepts_client_renegotiation = i
            else:
                raise
        except OpenSSLError as e:
            if "handshake failure" in e.args[0]:
                accepts_client_renegotiation = i
            elif "no renegotiation" in e.args[0]:
                accepts_client_renegotiation = i
            elif "tlsv1 unrecognized name" in e.args[0]:
                # Yahoo's very own way of rejecting a renegotiation
                accepts_client_renegotiation = i
            elif "tlsv1 alert internal error" in e.args[0]:
                # Jetty server: https://github.com/nabla-c0d3/sslyze/issues/290
                accepts_client_renegotiation = i
            elif "decryption failed or bad record mac" in e.args[0]:
                # Some servers such as reddit.com
                accepts_client_renegotiation = i
            elif "sslv3 alert unexpected message" in e.args[0]:
                # traefik https://github.com/nabla-c0d3/sslyze/issues/422
                accepts_client_renegotiation = i
            elif "shut down by peer" in e.args[0]:
                # Cloudfront
                accepts_client_renegotiation = i

            else:
                raise

    finally:
        ssl_connection.close()

    return _ScanJobResultEnum.ACCEPTS_CLIENT_RENEG, accepts_client_renegotiation
