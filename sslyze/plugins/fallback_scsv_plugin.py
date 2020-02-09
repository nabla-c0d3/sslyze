from concurrent.futures._base import Future
from dataclasses import dataclass
from typing import List, Optional
from nassl import _nassl
from nassl.ssl_client import OpenSslVersionEnum
from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanCommandExtraArguments,
    ScanJob,
    ScanCommandWrongUsageError,
)
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.connection_helpers.errors import ServerRejectedTlsHandshake


@dataclass(frozen=True)
class FallbackScsvScanResult(ScanCommandResult):
    """The result of testing a server for the TLS_FALLBACK_SCSV mechanism to prevent downgrade attacks.

    Attributes:
        supports_fallback_scsv: True if the server supports the TLS_FALLBACK_SCSV mechanism.
    """

    supports_fallback_scsv: bool


class FallbackScsvImplementation(ScanCommandImplementation):
    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [ScanJob(function_to_call=_test_scsv, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
        if len(completed_scan_jobs) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {completed_scan_jobs}")

        return FallbackScsvScanResult(supports_fallback_scsv=completed_scan_jobs[0].result())


def _test_scsv(server_info: ServerConnectivityInfo) -> bool:
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no downgrade possible with TLS 1.3
    if server_info.tls_probing_result.highest_tls_version_supported >= OpenSslVersionEnum.TLSV1_3:
        ssl_version_to_use = OpenSslVersionEnum.TLSV1_2
    else:
        ssl_version_to_use = server_info.tls_probing_result.highest_tls_version_supported

    # Try to connect using a lower TLS version with the fallback cipher suite enabled
    ssl_version_downgrade = OpenSslVersionEnum(ssl_version_to_use.value - 1)  # type: ignore
    ssl_connection = server_info.get_preconfigured_tls_connection(override_tls_version=ssl_version_downgrade)
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

    finally:
        ssl_connection.close()

    return supports_fallback_scsv


# TODO
class CliConnector:
    def as_text(self) -> List[str]:
        result_txt = [self._format_title(self.scan_command.get_title())]
        downgrade_txt = (
            "OK - Supported" if self.supports_fallback_scsv else "VULNERABLE - Signaling cipher suite not supported"
        )
        result_txt.append(self._format_field("TLS_FALLBACK_SCSV:", downgrade_txt))
        return result_txt
