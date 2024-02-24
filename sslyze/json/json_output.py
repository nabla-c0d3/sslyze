from datetime import datetime
from pathlib import Path
from typing import List, Optional, Any
from uuid import UUID

from pydantic import BaseModel, model_validator

from sslyze import (
    ServerNetworkConfiguration,
    ProtocolWithOpportunisticTlsEnum,
    ServerScanStatusEnum,
    ServerConnectivityStatusEnum,
    ClientAuthRequirementEnum,
)
from sslyze.__version__ import __url__, __version__
from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid, BaseModelWithOrmMode, StrFromEnumValueName
from sslyze.plugins.certificate_info.json_output import (
    CertificateInfoExtraArgumentAsJson,
    CertificateInfoScanAttemptAsJson,
)
from sslyze.plugins.compression_plugin import CompressionScanAttemptAsJson
from sslyze.plugins.early_data_plugin import EarlyDataScanAttemptAsJson
from sslyze.plugins.elliptic_curves_plugin import SupportedEllipticCurvesScanAttemptAsJson
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanAttemptAsJson
from sslyze.plugins.heartbleed_plugin import HeartbleedScanAttemptAsJson
from sslyze.plugins.http_headers_plugin import HttpHeadersScanAttemptAsJson
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanAttemptAsJson
from sslyze.plugins.openssl_cipher_suites.json_output import CipherSuitesScanAttemptAsJson
from sslyze.plugins.robot.implementation import RobotScanAttemptAsJson
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanAttemptAsJson

from sslyze.plugins.session_resumption.json_output import (
    SessionResumptionSupportExtraArgumentAsJson,
    SessionResumptionSupportScanAttemptAsJson,
)
from sslyze import (
    ServerScanResult,
    ServerTlsProbingResult,
)
from sslyze.scanner.models import AllScanCommandsAttempts
from sslyze.server_setting import ConnectionTypeEnum, ServerNetworkLocation


class ScanCommandsExtraArgumentsAsJson(BaseModelWithOrmModeAndForbid):
    # Field is present if extra arguments were provided for the corresponding scan command
    certificate_info: Optional[CertificateInfoExtraArgumentAsJson] = None
    session_resumption: Optional[SessionResumptionSupportExtraArgumentAsJson] = None


class AllScanCommandsAttemptsAsJson(BaseModelWithOrmModeAndForbid):
    certificate_info: CertificateInfoScanAttemptAsJson
    ssl_2_0_cipher_suites: CipherSuitesScanAttemptAsJson
    ssl_3_0_cipher_suites: CipherSuitesScanAttemptAsJson
    tls_1_0_cipher_suites: CipherSuitesScanAttemptAsJson
    tls_1_1_cipher_suites: CipherSuitesScanAttemptAsJson
    tls_1_2_cipher_suites: CipherSuitesScanAttemptAsJson
    tls_1_3_cipher_suites: CipherSuitesScanAttemptAsJson
    tls_compression: CompressionScanAttemptAsJson
    tls_1_3_early_data: EarlyDataScanAttemptAsJson
    openssl_ccs_injection: OpenSslCcsInjectionScanAttemptAsJson
    tls_fallback_scsv: FallbackScsvScanAttemptAsJson
    heartbleed: HeartbleedScanAttemptAsJson
    robot: RobotScanAttemptAsJson
    session_renegotiation: SessionRenegotiationScanAttemptAsJson
    session_resumption: SessionResumptionSupportScanAttemptAsJson
    elliptic_curves: SupportedEllipticCurvesScanAttemptAsJson
    http_headers: HttpHeadersScanAttemptAsJson

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, AllScanCommandsAttempts):
            return data

        all_scan_commands_attempts: AllScanCommandsAttempts = data
        all_scan_commands_attempts_json = {}
        for field_name, field in cls.model_fields.items():
            scan_command_attempt = getattr(all_scan_commands_attempts, field_name)

            # Convert the error trace to a string; this is why we have to implement a model_validator()
            error_trace_as_str = None
            if scan_command_attempt.error_trace:
                error_trace_as_str = ""
                for line in scan_command_attempt.error_trace.format(chain=False):
                    error_trace_as_str += line

            # Create the JSON version of the scan command attempt
            scan_command_attempt_json_cls = field.annotation  # Assumes pydantic 2.x

            assert scan_command_attempt_json_cls  # Can never be None
            all_scan_commands_attempts_json[field_name] = scan_command_attempt_json_cls(
                status=scan_command_attempt.status,
                error_reason=scan_command_attempt.error_reason,
                error_trace=error_trace_as_str,
                result=scan_command_attempt.result,
            )

        return all_scan_commands_attempts_json


# Identical fields in the JSON output
class _HttpProxySettingsAsJson(BaseModelWithOrmModeAndForbid):
    hostname: str
    port: int

    basic_auth_user: Optional[str] = None
    basic_auth_password: Optional[str] = None


class _ClientAuthenticationCredentialsAsJson(BaseModelWithOrmMode):
    # Compared to the ClientAuthenticationCredentials class, this model does not have the key_password field
    certificate_chain_path: Path
    key_path: Path
    key_type: StrFromEnumValueName


class _ServerTlsProbingResultAsJson(BaseModelWithOrmModeAndForbid):
    highest_tls_version_supported: StrFromEnumValueName
    cipher_suite_supported: str
    client_auth_requirement: ClientAuthRequirementEnum
    supports_ecdh_key_exchange: bool


assert ServerTlsProbingResult.__doc__
_ServerTlsProbingResultAsJson.__doc__ = ServerTlsProbingResult.__doc__


class _ServerNetworkConfigurationAsJson(BaseModelWithOrmModeAndForbid):
    tls_server_name_indication: str
    tls_opportunistic_encryption: Optional[ProtocolWithOpportunisticTlsEnum] = None
    tls_client_auth_credentials: Optional[_ClientAuthenticationCredentialsAsJson] = None

    xmpp_to_hostname: Optional[str] = None

    network_timeout: int = 5
    network_max_retries: int = 3


assert ServerNetworkConfiguration.__doc__
_ServerNetworkConfigurationAsJson.__doc__ = ServerNetworkConfiguration.__doc__


class _ServerNetworkLocationAsJson(BaseModelWithOrmModeAndForbid):
    hostname: str
    port: int
    connection_type: ConnectionTypeEnum
    ip_address: Optional[str] = None
    http_proxy_settings: Optional[_HttpProxySettingsAsJson] = None


assert ServerNetworkLocation.__doc__
_ServerNetworkLocationAsJson.__doc__ = ServerNetworkLocation.__doc__


class ServerScanResultAsJson(BaseModelWithOrmModeAndForbid):
    uuid: UUID
    server_location: _ServerNetworkLocationAsJson
    network_configuration: _ServerNetworkConfigurationAsJson

    connectivity_status: ServerConnectivityStatusEnum
    connectivity_error_trace: Optional[str]
    connectivity_result: Optional[_ServerTlsProbingResultAsJson]

    scan_status: ServerScanStatusEnum
    scan_result: Optional[AllScanCommandsAttemptsAsJson]

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, ServerScanResult):
            return data

        server_scan_result: ServerScanResult = data
        connectivity_error_trace_as_str = None
        if server_scan_result.connectivity_error_trace:
            connectivity_error_trace_as_str = ""
            for line in server_scan_result.connectivity_error_trace.format(chain=False):
                connectivity_error_trace_as_str += line

        connectivity_result_as_json: Optional[_ServerTlsProbingResultAsJson]
        if server_scan_result.connectivity_result:
            connectivity_result_as_json = _ServerTlsProbingResultAsJson.model_validate(
                server_scan_result.connectivity_result
            )
        else:
            connectivity_result_as_json = None

        scan_result_as_json: Optional[AllScanCommandsAttemptsAsJson]
        if server_scan_result.scan_result:
            scan_result_as_json = AllScanCommandsAttemptsAsJson.model_validate(server_scan_result.scan_result)
        else:
            scan_result_as_json = None

        return dict(
            uuid=server_scan_result.uuid,
            server_location=_ServerNetworkLocationAsJson.model_validate(server_scan_result.server_location),
            network_configuration=_ServerNetworkConfigurationAsJson.model_validate(
                server_scan_result.network_configuration
            ),
            connectivity_status=server_scan_result.connectivity_status,
            connectivity_error_trace=connectivity_error_trace_as_str,
            connectivity_result=connectivity_result_as_json,
            scan_status=server_scan_result.scan_status,
            scan_result=scan_result_as_json,
        )


assert ServerScanResult.__doc__
ServerScanResultAsJson.__doc__ = ServerScanResult.__doc__


class InvalidServerStringAsJson(BaseModelWithOrmModeAndForbid):
    """A hostname:port string supplied via the command line that SSLyze was unable to parse or resolve."""

    server_string: str
    error_message: str


class SslyzeOutputAsJson(BaseModel):
    """The "root" dictionary of the JSON output when using the --json command line option."""

    invalid_server_strings: List[InvalidServerStringAsJson]
    server_scan_results: List[ServerScanResultAsJson]

    date_scans_started: datetime
    date_scans_completed: datetime

    sslyze_version: str = __version__
    sslyze_url: str = __url__
