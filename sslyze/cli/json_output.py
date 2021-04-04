from pathlib import Path
from typing import TextIO, List, Optional, Set

import pydantic
from nassl.ssl_client import OpenSslFileTypeEnum

from sslyze import ServerNetworkConfiguration, HttpProxySettings, ProtocolWithOpportunisticTlsEnum
from sslyze.__version__ import __url__, __version__
from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.cli.output_generator import OutputGenerator
from sslyze.errors import ConnectionToServerFailed
from sslyze.plugins.certificate_info.json_output import (
    CertificateInfoExtraArgumentAsJson,
    CertificateInfoScanResultAsJson,
)
from sslyze.plugins.compression_plugin import CompressionScanResultAsJson
from sslyze.plugins.early_data_plugin import EarlyDataScanResultAsJson
from sslyze.plugins.elliptic_curves_plugin import SupportedEllipticCurvesScanResultAsJson
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanResultAsJson
from sslyze.plugins.heartbleed_plugin import HeartbleedScanResultAsJson
from sslyze.plugins.http_headers_plugin import HttpHeadersScanResultAsJson
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanResultAsJson
from sslyze.plugins.openssl_cipher_suites.json_output import CipherSuitesScanResultAsJson
from sslyze.plugins.robot.implementation import RobotScanResultAsJson
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanResultAsJson

from sslyze.plugins.session_resumption.json_output import (
    SessionResumptionSupportExtraArgumentAsJson,
    SessionResumptionSupportScanResultAsJson,
)
from sslyze import (
    ServerScanResult,
    ScanCommand,
    ScanCommandErrorReasonEnum,
    ScanCommandError,
    ServerTlsProbingResult,
    ServerConnectivityInfo,
)


class _BaseModelWithOrmModeAndForbid(pydantic.BaseModel):
    class Config:
        orm_mode = True
        extra = "forbid"  # Fields must match between the JSON representation and the actual objects


class ScanCommandsExtraArgumentsAsJson(_BaseModelWithOrmModeAndForbid):
    # Field is present if extra arguments were provided for the corresponding scan command
    certificate_info: Optional[CertificateInfoExtraArgumentAsJson] = None
    session_resumption: Optional[SessionResumptionSupportExtraArgumentAsJson] = None


class ScanCommandErrorAsJson(_BaseModelWithOrmModeAndForbid):
    scan_command: ScanCommand
    reason: ScanCommandErrorReasonEnum
    exception_trace: str

    @classmethod
    def from_orm(cls, scan_cmd_error: ScanCommandError) -> "ScanCommandErrorAsJson":
        exception_trace_as_str = ""
        for line in scan_cmd_error.exception_trace.format(chain=False):
            exception_trace_as_str += line
        return cls(
            scan_command=scan_cmd_error.scan_command,
            reason=scan_cmd_error.reason,
            exception_trace=exception_trace_as_str,
        )


class ScanCommandsResultsAsJson(_BaseModelWithOrmModeAndForbid):
    # Field is present if the corresponding scan command was scheduled and was run successfully
    certificate_info: Optional[CertificateInfoScanResultAsJson] = None
    ssl_2_0_cipher_suites: Optional[CipherSuitesScanResultAsJson] = None
    ssl_3_0_cipher_suites: Optional[CipherSuitesScanResultAsJson] = None
    tls_1_0_cipher_suites: Optional[CipherSuitesScanResultAsJson] = None
    tls_1_1_cipher_suites: Optional[CipherSuitesScanResultAsJson] = None
    tls_1_2_cipher_suites: Optional[CipherSuitesScanResultAsJson] = None
    tls_1_3_cipher_suites: Optional[CipherSuitesScanResultAsJson] = None
    tls_compression: Optional[CompressionScanResultAsJson] = None  # type: ignore
    tls_1_3_early_data: Optional[EarlyDataScanResultAsJson] = None  # type: ignore
    openssl_ccs_injection: Optional[OpenSslCcsInjectionScanResultAsJson] = None  # type: ignore
    tls_fallback_scsv: Optional[FallbackScsvScanResultAsJson] = None  # type: ignore
    heartbleed: Optional[HeartbleedScanResultAsJson] = None  # type: ignore
    robot: Optional[RobotScanResultAsJson] = None  # type: ignore
    session_renegotiation: Optional[SessionRenegotiationScanResultAsJson] = None  # type: ignore
    session_resumption: Optional[SessionResumptionSupportScanResultAsJson] = None
    http_headers: Optional[HttpHeadersScanResultAsJson] = None
    elliptic_curves: Optional[SupportedEllipticCurvesScanResultAsJson] = None


# Identical fields in the JSON output
_ServerTlsProbingResultAsJson = pydantic.dataclasses.dataclass(ServerTlsProbingResult, frozen=True)
_HttpProxySettingsAsJson = pydantic.dataclasses.dataclass(HttpProxySettings, frozen=True)


class _ClientAuthenticationCredentialsAsJson(pydantic.BaseModel):
    # Compared to the ClientAuthenticationCredentials class, this model does not have the key_password field
    certificate_chain_path: Path
    key_path: Path
    key_type: OpenSslFileTypeEnum = OpenSslFileTypeEnum.PEM

    class Config:
        orm_mode = True


class _ServerNetworkConfigurationAsJson(_BaseModelWithOrmModeAndForbid):
    tls_server_name_indication: str
    tls_opportunistic_encryption: Optional[ProtocolWithOpportunisticTlsEnum] = None
    tls_client_auth_credentials: Optional[_ClientAuthenticationCredentialsAsJson] = None

    xmpp_to_hostname: Optional[str] = None

    network_timeout: int = 5
    network_max_retries: int = 3


_ServerNetworkConfigurationAsJson.__doc__ = ServerNetworkConfiguration.__doc__  # type: ignore


class _ServerNetworkLocationAsJson(_BaseModelWithOrmModeAndForbid):
    """All the information needed to connect to a server.

    Attributes:
        hostname: The server's hostname.
        port: The server's TLS port number.
        ip_address: The server's IP address. This field is null if scans are tunneled through a proxy.
        http_proxy_settings: The HTTP proxy configuration to use in order to tunnel the scans through a proxy. The
            proxy will be responsible for looking up the server's IP address and connecting to it. This field is null
            if no proxy was used for the scan.
    """

    hostname: str
    port: int

    # Set if SSLyze is directly connecting to the server (ie. no proxy is being used)
    ip_address: Optional[str] = None

    # Set if SSLyze is connecting via a proxy
    http_proxy_settings: Optional[_HttpProxySettingsAsJson] = None  # type: ignore


class _ServerConnectivityInfoAsJson(_BaseModelWithOrmModeAndForbid):
    server_location: _ServerNetworkLocationAsJson
    network_configuration: _ServerNetworkConfigurationAsJson
    tls_probing_result: _ServerTlsProbingResultAsJson  # type: ignore


_ServerConnectivityInfoAsJson.__doc__ = ServerConnectivityInfo.__doc__  # type: ignore


class ServerScanResultAsJson(_BaseModelWithOrmModeAndForbid):
    server_info: _ServerConnectivityInfoAsJson
    scan_commands: Set[ScanCommand]
    scan_commands_extra_arguments: ScanCommandsExtraArgumentsAsJson

    scan_commands_results: ScanCommandsResultsAsJson
    scan_commands_errors: List[ScanCommandErrorAsJson]  # Empty if no errors occurred


class _ServerConnectivityErrorAsJson(pydantic.BaseModel):
    server_string: str
    error_message: str


class SslyzeOutputAsJson(pydantic.BaseModel):
    """The "root" dictionary of the JSON output when using the --json command line option.
    """

    server_scan_results: List[ServerScanResultAsJson]
    server_connectivity_errors: List[_ServerConnectivityErrorAsJson]
    total_scan_time: float
    sslyze_version: str = __version__
    sslyze_url: str = __url__


class JsonOutputGenerator(OutputGenerator):
    def __init__(self, file_to: TextIO) -> None:
        super().__init__(file_to)
        self._server_connectivity_errors: List[_ServerConnectivityErrorAsJson] = []
        self._server_scan_results: List[ServerScanResult] = []

    def command_line_parsed(self, parsed_command_line: ParsedCommandLine) -> None:
        for bad_server_str in parsed_command_line.invalid_servers:
            self._server_connectivity_errors.append(
                _ServerConnectivityErrorAsJson(
                    server_string=bad_server_str.server_string, error_message=bad_server_str.error_message
                )
            )

    def server_connectivity_test_failed(self, connectivity_error: ConnectionToServerFailed) -> None:
        hostname = connectivity_error.server_location.hostname
        port = connectivity_error.server_location.port
        self._server_connectivity_errors.append(
            _ServerConnectivityErrorAsJson(
                server_string=f"{hostname}:{port}", error_message=connectivity_error.error_message,
            )
        )

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        pass

    def scans_started(self) -> None:
        pass

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        self._server_scan_results.append(server_scan_result)

    def scans_completed(self, total_scan_time: float) -> None:
        final_json_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.from_orm(result) for result in self._server_scan_results],
            server_connectivity_errors=self._server_connectivity_errors,
            total_scan_time=total_scan_time,
        )
        json_out = final_json_output.json(sort_keys=True, indent=4, ensure_ascii=True)
        self._file_to.write(json_out)
