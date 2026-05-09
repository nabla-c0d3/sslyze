from dataclasses import dataclass
from typing import List, Optional

from nassl.openssl_1_1_1.ssl_client import ExtendedMasterSecretSupportEnum
from nassl.openssl_1_1_1.ssl_client import SslClient_OpenSSL_1_1_1

from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.connection_helpers.tls_connection import OpenSslVersionEnum
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


@dataclass(frozen=True)
class EmsExtensionScanResult(ScanCommandResult):
    """The result of testing a server for TLS Extended Master Secret extension support.

    Attributes:
        supports_ems_extension: True if the server supports the TLS Extended Master Secret extension.
    """

    supports_ems_extension: bool


class EmsExtensionScanResultAsJson(BaseModelWithOrmModeAndForbid):
    supports_ems_extension: bool


class EmsExtensionScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[EmsExtensionScanResultAsJson]


class _EmsExtensionCliConnector(ScanCommandCliConnector[EmsExtensionScanResult, None]):
    _cli_option = "ems"
    _cli_description = "Test a server for TLS Extended Master Secret extension support."

    @classmethod
    def result_to_console_output(cls, result: EmsExtensionScanResult) -> List[str]:
        result_as_txt = [cls._format_title("TLS Extended Master Secret Extension")]
        downgrade_txt = "OK - Supported" if result.supports_ems_extension else "VULNERABLE - EMS not supported"
        result_as_txt.append(cls._format_field("", downgrade_txt))
        return result_as_txt


class EmsExtensionImplementation(ScanCommandImplementation[EmsExtensionScanResult, None]):
    """Test a server for TLS Extended Master Secret extension support."""

    cli_connector_cls = _EmsExtensionCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [ScanJob(function_to_call=_test_ems, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> EmsExtensionScanResult:
        if len(scan_job_results) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        return EmsExtensionScanResult(supports_ems_extension=scan_job_results[0].get_result())


def _test_ems(server_info: ServerConnectivityInfo) -> bool:
    # The Extended Master Secret extension is not relevant to TLS 1.3 and later
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        return True

    ssl_connection = server_info.get_preconfigured_tls_connection(
        # Only the 1.1.1+ client has EMS support
        openssl_version=OpenSslVersionEnum.OPENSSL_1_1_1,
    )
    if not isinstance(ssl_connection.ssl_client, SslClient_OpenSSL_1_1_1):
        raise RuntimeError("Should never happen")

    # Perform the SSL handshake
    try:
        ssl_connection.connect()
        ems_support_enum = ssl_connection.ssl_client.get_extended_master_secret_support()
    finally:
        ssl_connection.close()

    # Return the result
    if ems_support_enum == ExtendedMasterSecretSupportEnum.NOT_USED_IN_CURRENT_SESSION:
        return False
    elif ems_support_enum == ExtendedMasterSecretSupportEnum.USED_IN_CURRENT_SESSION:
        return True
    else:
        raise ValueError("Could not determine Extended Master Secret Extension support")
