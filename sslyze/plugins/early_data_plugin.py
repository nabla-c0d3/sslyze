from dataclasses import dataclass
from typing import List, Optional

import socket
import pydantic
from nassl._nassl import OpenSSLError
from nassl.ssl_client import OpenSslEarlyDataStatusEnum, SslClient

from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanCommandExtraArgument,
    ScanJob,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
    ScanJobResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum
from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.connection_helpers.http_request_generator import HttpRequestGenerator


@dataclass(frozen=True)
class EarlyDataScanResult(ScanCommandResult):
    """The result of testing a server for TLS 1.3 early data support.

    Attributes:
        supports_early_data: True if the server accepted early data.
    """

    supports_early_data: bool


# Identical fields in the JSON output
EarlyDataScanResultAsJson = pydantic.dataclasses.dataclass(EarlyDataScanResult, frozen=True)


class EarlyDataScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[EarlyDataScanResultAsJson]  # type: ignore


class _EarlyDataCliConnector(ScanCommandCliConnector[EarlyDataScanResult, None]):

    _cli_option = "early_data"
    _cli_description = "Test a server for TLS 1.3 early data support."

    @classmethod
    def result_to_console_output(cls, result: EarlyDataScanResult) -> List[str]:
        result_as_txt = [cls._format_title("TLS 1.3 Early Data")]
        if result.supports_early_data:
            result_as_txt.append(cls._format_field("", "Suppported - Server accepted early data"))
        else:
            result_as_txt.append(cls._format_field("", "Not Supported"))
        return result_as_txt


class EarlyDataImplementation(ScanCommandImplementation[EarlyDataScanResult, None]):
    """Test the server(s) for TLS 1.3 early data support.

    This will only work for HTTPS servers; other TLS servers (SMTP, POP3, etc.) are not supported.
    """

    cli_connector_cls = _EarlyDataCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [ScanJob(function_to_call=_test_early_data_support, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> EarlyDataScanResult:
        if len(scan_job_results) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        return EarlyDataScanResult(supports_early_data=scan_job_results[0].get_result())


def _test_early_data_support(server_info: ServerConnectivityInfo) -> bool:
    session = None
    is_early_data_supported = False
    ssl_connection = server_info.get_preconfigured_tls_connection(override_tls_version=TlsVersionEnum.TLS_1_3)
    try:
        # Perform an SSL handshake and keep the session
        ssl_connection.connect()
        # Send and receive data for the TLS session to be created
        ssl_connection.ssl_client.write(HttpRequestGenerator.get_request(host=server_info.server_location.hostname))
        ssl_connection.ssl_client.read(2048)
        session = ssl_connection.ssl_client.get_session()
    except ServerRejectedTlsHandshake:
        # TLS 1.3 not supported
        is_early_data_supported = False
    except TlsHandshakeTimedOut:
        # Sometimes triggered by servers that don't support TLS 1.3 at all, such as Amazon Cloudfront
        is_early_data_supported = False
    except socket.timeout:
        # Some servers just don't answer the read() call
        is_early_data_supported = False
    finally:
        ssl_connection.close()

    # Then try to re-use the session and send early data
    if session is not None:
        ssl_connection2 = server_info.get_preconfigured_tls_connection(override_tls_version=TlsVersionEnum.TLS_1_3)
        if not isinstance(ssl_connection2.ssl_client, SslClient):
            raise RuntimeError("Should never happen")

        ssl_connection2.ssl_client.set_session(session)

        try:
            # Open a socket to the server but don't do the actual TLS handshake
            ssl_connection2._do_pre_handshake()

            # Send one byte of early data
            ssl_connection2.ssl_client.write_early_data(b"E")
            ssl_connection2.ssl_client.do_handshake()
            if ssl_connection2.ssl_client.get_early_data_status() == OpenSslEarlyDataStatusEnum.ACCEPTED:
                is_early_data_supported = True
            else:
                is_early_data_supported = False

        except OpenSSLError as e:
            if "function you should not call" in e.args[0]:
                # This is what OpenSSL returns when the server did not enable early data
                is_early_data_supported = False
            else:
                raise

        finally:
            ssl_connection2.close()

    return is_early_data_supported
