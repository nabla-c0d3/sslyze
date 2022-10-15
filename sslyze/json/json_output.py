from datetime import datetime
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING
from uuid import UUID

import pydantic

from sslyze import (
    ServerNetworkConfiguration,
    ProtocolWithOpportunisticTlsEnum,
    ServerScanStatusEnum,
    ServerConnectivityStatusEnum,
    ClientAuthRequirementEnum,
    ClientAuthenticationCredentials,
)
from sslyze.__version__ import __url__, __version__
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

if TYPE_CHECKING:
    from sslyze.cli.server_string_parser import InvalidServerStringError


class _BaseModelWithOrmModeAndForbid(pydantic.BaseModel):
    class Config:
        orm_mode = True
        extra = "forbid"  # Fields must match between the JSON representation and the actual objects


class ScanCommandsExtraArgumentsAsJson(_BaseModelWithOrmModeAndForbid):
    # Field is present if extra arguments were provided for the corresponding scan command
    certificate_info: Optional[CertificateInfoExtraArgumentAsJson] = None
    session_resumption: Optional[SessionResumptionSupportExtraArgumentAsJson] = None


class AllScanCommandsAttemptsAsJson(_BaseModelWithOrmModeAndForbid):
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

    @classmethod
    def from_orm(cls, all_scan_commands_attempts: AllScanCommandsAttempts) -> "AllScanCommandsAttemptsAsJson":
        all_scan_commands_attempts_json = {}
        for field_name, field in cls.__fields__.items():
            scan_command_attempt = getattr(all_scan_commands_attempts, field_name)

            # Convert the error trace to a string; this is why we have to override from_orm()
            error_trace_as_str = None
            if scan_command_attempt.error_trace:
                error_trace_as_str = ""
                for line in scan_command_attempt.error_trace.format(chain=False):
                    error_trace_as_str += line

            # Create the JSON version of the scan command attempt
            scan_command_attempt_json_cls = field.type_
            all_scan_commands_attempts_json[field_name] = scan_command_attempt_json_cls(
                status=scan_command_attempt.status,
                error_reason=scan_command_attempt.error_reason,
                error_trace=error_trace_as_str,
                result=scan_command_attempt.result,
            )

        return cls(**all_scan_commands_attempts_json)


# Identical fields in the JSON output
class _HttpProxySettingsAsJson(pydantic.BaseModel):
    hostname: str
    port: int

    basic_auth_user: Optional[str] = None
    basic_auth_password: Optional[str] = None


class _ClientAuthenticationCredentialsAsJson(pydantic.BaseModel):
    # Compared to the ClientAuthenticationCredentials class, this model does not have the key_password field
    certificate_chain_path: Path
    key_path: Path
    key_type: str

    class Config:
        orm_mode = True

    @classmethod
    def from_orm(cls, client_auth_creds: "ClientAuthenticationCredentials") -> "_ClientAuthenticationCredentialsAsJson":
        return cls(
            certificate_chain_path=client_auth_creds.certificate_chain_path,
            key_path=client_auth_creds.key_path,
            key_type=client_auth_creds.key_type.name,
        )


class _ServerTlsProbingResultAsJson(_BaseModelWithOrmModeAndForbid):
    highest_tls_version_supported: str
    cipher_suite_supported: str
    client_auth_requirement: ClientAuthRequirementEnum
    supports_ecdh_key_exchange: bool

    @classmethod
    def from_orm(cls, tls_probing_result: ServerTlsProbingResult) -> "_ServerTlsProbingResultAsJson":
        return cls(
            highest_tls_version_supported=tls_probing_result.highest_tls_version_supported.name,
            cipher_suite_supported=tls_probing_result.cipher_suite_supported,
            client_auth_requirement=tls_probing_result.client_auth_requirement,
            supports_ecdh_key_exchange=tls_probing_result.supports_ecdh_key_exchange,
        )


_ServerTlsProbingResultAsJson.__doc__ = ServerTlsProbingResult.__doc__  # type: ignore


class _ServerNetworkConfigurationAsJson(_BaseModelWithOrmModeAndForbid):
    tls_server_name_indication: str
    tls_opportunistic_encryption: Optional[ProtocolWithOpportunisticTlsEnum] = None
    tls_client_auth_credentials: Optional[_ClientAuthenticationCredentialsAsJson] = None

    xmpp_to_hostname: Optional[str] = None

    network_timeout: int = 5
    network_max_retries: int = 3


_ServerNetworkConfigurationAsJson.__doc__ = ServerNetworkConfiguration.__doc__  # type: ignore


class _ServerNetworkLocationAsJson(_BaseModelWithOrmModeAndForbid):
    hostname: str
    port: int
    connection_type: ConnectionTypeEnum
    ip_address: Optional[str] = None
    http_proxy_settings: Optional[_HttpProxySettingsAsJson] = None  # type: ignore


_ServerNetworkLocationAsJson.__doc__ = ServerNetworkLocation.__doc__  # type: ignore


class ServerScanResultAsJson(_BaseModelWithOrmModeAndForbid):
    uuid: UUID
    server_location: _ServerNetworkLocationAsJson
    network_configuration: _ServerNetworkConfigurationAsJson

    connectivity_status: ServerConnectivityStatusEnum
    connectivity_error_trace: Optional[str]
    connectivity_result: Optional[_ServerTlsProbingResultAsJson]

    scan_status: ServerScanStatusEnum
    scan_result: Optional[AllScanCommandsAttemptsAsJson]

    @classmethod
    def from_orm(cls, server_scan_result: ServerScanResult) -> "ServerScanResultAsJson":
        connectivity_error_trace_as_str = None
        if server_scan_result.connectivity_error_trace:
            connectivity_error_trace_as_str = ""
            for line in server_scan_result.connectivity_error_trace.format(chain=False):
                connectivity_error_trace_as_str += line

        connectivity_result_as_json: Optional[_ServerTlsProbingResultAsJson]
        if server_scan_result.connectivity_result:
            connectivity_result_as_json = _ServerTlsProbingResultAsJson.from_orm(server_scan_result.connectivity_result)
        else:
            connectivity_result_as_json = None

        scan_result_as_json: Optional[AllScanCommandsAttemptsAsJson]
        if server_scan_result.scan_result:
            scan_result_as_json = AllScanCommandsAttemptsAsJson.from_orm(server_scan_result.scan_result)
        else:
            scan_result_as_json = None

        return cls(
            uuid=server_scan_result.uuid,
            server_location=_ServerNetworkLocationAsJson.from_orm(server_scan_result.server_location),
            network_configuration=_ServerNetworkConfigurationAsJson.from_orm(server_scan_result.network_configuration),
            connectivity_status=server_scan_result.connectivity_status,
            connectivity_error_trace=connectivity_error_trace_as_str,
            connectivity_result=connectivity_result_as_json,
            scan_status=server_scan_result.scan_status,
            scan_result=scan_result_as_json,
        )


ServerScanResultAsJson.__doc__ = ServerScanResult.__doc__  # type: ignore


class InvalidServerStringAsJson(_BaseModelWithOrmModeAndForbid):
    """A hostname:port string supplied via the command line that SSLyze was unable to parse or resolve."""

    server_string: str
    error_message: str

    @classmethod
    def from_orm(cls, invalid_server_string_error: "InvalidServerStringError") -> "InvalidServerStringAsJson":
        return cls(
            server_string=invalid_server_string_error.server_string,
            error_message=invalid_server_string_error.error_message,
        )


class SslyzeOutputAsJson(pydantic.BaseModel):
    """The "root" dictionary of the JSON output when using the --json command line option."""

    invalid_server_strings: List[InvalidServerStringAsJson] = []  # TODO(AD): Remove default value starting with v6.x.x
    server_scan_results: List[ServerScanResultAsJson]

    date_scans_started: datetime
    date_scans_completed: datetime

    sslyze_version: str = __version__
    sslyze_url: str = __url__
