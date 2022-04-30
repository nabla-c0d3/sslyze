from dataclasses import dataclass
from typing import List, Optional

import pydantic
from nassl import _nassl
from nassl.legacy_ssl_client import LegacySslClient

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


@dataclass(frozen=True)
class FallbackScsvScanResult(ScanCommandResult):
    """The result of testing a server for the TLS_FALLBACK_SCSV mechanism to prevent downgrade attacks.

    Attributes:
        supports_fallback_scsv: True if the server supports the TLS_FALLBACK_SCSV mechanism.
    """

    supports_fallback_scsv: bool


# Identical fields in the JSON output
FallbackScsvScanResultAsJson = pydantic.dataclasses.dataclass(FallbackScsvScanResult, frozen=True)


class FallbackScsvScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[FallbackScsvScanResultAsJson]  # type: ignore


class _FallbackScsvCliConnector(ScanCommandCliConnector[FallbackScsvScanResult, None]):

    _cli_option = "fallback"
    _cli_description = "Test a server for the TLS_FALLBACK_SCSV mechanism to prevent downgrade attacks."

    @classmethod
    def result_to_console_output(cls, result: FallbackScsvScanResult) -> List[str]:
        result_as_txt = [cls._format_title("Downgrade Attacks")]
        downgrade_txt = (
            "OK - Supported" if result.supports_fallback_scsv else "VULNERABLE - Signaling cipher suite not supported"
        )
        result_as_txt.append(cls._format_field("TLS_FALLBACK_SCSV:", downgrade_txt))
        return result_as_txt


class FallbackScsvImplementation(ScanCommandImplementation[FallbackScsvScanResult, None]):
    """Test a server for the TLS_FALLBACK_SCSV mechanism to prevent downgrade attacks."""

    cli_connector_cls = _FallbackScsvCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [ScanJob(function_to_call=_test_scsv, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> FallbackScsvScanResult:
        if len(scan_job_results) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        return FallbackScsvScanResult(supports_fallback_scsv=scan_job_results[0].get_result())


def _test_scsv(server_info: ServerConnectivityInfo) -> bool:
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no downgrade possible with TLS 1.3
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        ssl_version_to_use = TlsVersionEnum.TLS_1_2
    else:
        ssl_version_to_use = server_info.tls_probing_result.highest_tls_version_supported

    # Try to connect using a lower TLS version with the fallback cipher suite enabled
    ssl_version_downgrade = TlsVersionEnum(ssl_version_to_use.value - 1)
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=ssl_version_downgrade,
        # Only the legacy client has enable_fallback_scsv()
        should_use_legacy_openssl=True,
    )
    if not isinstance(ssl_connection.ssl_client, LegacySslClient):
        raise RuntimeError("Should never happen")

    ssl_connection.ssl_client.enable_fallback_scsv()

    supports_fallback_scsv = False
    try:
        # Perform the SSL handshake
        ssl_connection.connect()

    except _nassl.OpenSSLError as e:
        # This is the right, specific alert the server should return
        if "tlsv1 alert inappropriate fallback" in str(e.args):
            supports_fallback_scsv = True
        else:
            raise

    except ServerRejectedTlsHandshake:
        # If the handshake is rejected, we assume downgrade attacks are prevented (this is how F5 balancers do it)
        # although it could also be because the server does not support this version of TLS
        # https://github.com/nabla-c0d3/sslyze/issues/119
        supports_fallback_scsv = True

    except TlsHandshakeTimedOut:
        # Sometimes triggered by servers that don't support (at all) a specific version of TLS
        # Amazon Cloudfront does that with TLS 1.3
        supports_fallback_scsv = True

    finally:
        ssl_connection.close()

    return supports_fallback_scsv
