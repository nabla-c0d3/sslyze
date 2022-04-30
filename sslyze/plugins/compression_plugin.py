from dataclasses import dataclass

import pydantic
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import ClientCertificateRequested

from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanJob,
    ScanCommandExtraArgument,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
    ScanJobResult,
)
from typing import List, Optional

from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum
from sslyze.errors import ServerRejectedTlsHandshake


@dataclass(frozen=True)
class CompressionScanResult(ScanCommandResult):
    """The result of testing a server for TLS compression support.

    Attributes:
        supports_compression: True if TLS compression is supported by the server, thereby enabling the CRIME attack.
    """

    supports_compression: bool


# Identical fields in the JSON output
CompressionScanResultAsJson = pydantic.dataclasses.dataclass(CompressionScanResult, frozen=True)


class CompressionScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[CompressionScanResultAsJson]  # type: ignore


class _CompressionCliConnector(ScanCommandCliConnector[CompressionScanResult, None]):

    _cli_option = "compression"
    _cli_description = "Test a server for TLS compression support, which can be leveraged to perform a CRIME attack."

    @classmethod
    def result_to_console_output(cls, result: CompressionScanResult) -> List[str]:
        result_as_txt = [cls._format_title("Deflate Compression")]
        if result.supports_compression:
            result_as_txt.append(cls._format_field("", "VULNERABLE - Server supports Deflate compression"))
        else:
            result_as_txt.append(cls._format_field("", "OK - Compression disabled"))
        return result_as_txt


class CompressionImplementation(ScanCommandImplementation[CompressionScanResult, None]):
    """Test a server for TLS compression support, which can be leveraged to perform a CRIME attack."""

    cli_connector_cls = _CompressionCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [ScanJob(function_to_call=_test_compression_support, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> CompressionScanResult:
        if len(scan_job_results) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        return CompressionScanResult(supports_compression=scan_job_results[0].get_result())


def _test_compression_support(server_info: ServerConnectivityInfo) -> bool:
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no compression with TLS 1.3
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        tls_version_to_use = TlsVersionEnum.TLS_1_2
        downgraded_from_tls_1_3 = True
    else:
        tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported
        downgraded_from_tls_1_3 = False

    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version_to_use,
        should_use_legacy_openssl=True,  # Only the legacy SSL client has methods to check for compression support
    )
    if not isinstance(ssl_connection.ssl_client, LegacySslClient):
        raise RuntimeError("Should never happen")

    # Make sure OpenSSL was built with support for compression to avoid false negatives
    if "zlib compression" not in ssl_connection.ssl_client.get_available_compression_methods():
        raise RuntimeError("OpenSSL was not built with support for zlib / compression. Did you build nassl yourself ?")

    compression_name: Optional[str]
    try:
        # Perform the TLS handshake
        ssl_connection.connect()
        compression_name = ssl_connection.ssl_client.get_current_compression_method()

    except ClientCertificateRequested:
        compression_name = ssl_connection.ssl_client.get_current_compression_method()

    # Should only happen when the server only supports TLS 1.3, which does not support compression
    except ServerRejectedTlsHandshake:
        if downgraded_from_tls_1_3:
            compression_name = None
        else:
            raise

    finally:
        ssl_connection.close()

    return True if compression_name else False
