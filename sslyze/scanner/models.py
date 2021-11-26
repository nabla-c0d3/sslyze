from dataclasses import dataclass, fields, field
from enum import Enum
from traceback import TracebackException
from typing import Set, Optional, Type
from uuid import UUID, uuid4

from sslyze import ServerNetworkConfiguration
from sslyze.plugins.elliptic_curves_plugin import SupportedEllipticCurvesScanResult


from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult, CertificateInfoExtraArgument
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.early_data_plugin import EarlyDataScanResult
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanResult
from sslyze.plugins.heartbleed_plugin import HeartbleedScanResult
from sslyze.plugins.http_headers_plugin import HttpHeadersScanResult
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanResult
from sslyze.plugins.openssl_cipher_suites.implementation import CipherSuitesScanResult
from sslyze.plugins.robot.implementation import RobotScanResult
from sslyze.plugins.scan_commands import ScanCommand, ScanCommandsRepository
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanResult
from sslyze.plugins.session_resumption.implementation import (
    SessionResumptionSupportScanResult,
    SessionResumptionSupportExtraArgument,
)
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
from sslyze.server_connectivity import ServerTlsProbingResult
from sslyze.server_setting import ServerNetworkLocation


@dataclass(frozen=True)
class ScanCommandsExtraArguments:
    # Field is present if extra arguments were provided for the corresponding scan command
    certificate_info: Optional[CertificateInfoExtraArgument] = None
    session_resumption: Optional[SessionResumptionSupportExtraArgument] = None


@dataclass(frozen=True)
class ServerScanRequest:
    """A request to scan a specific server.

    Args:
        server_location: The server to scan.
        network_configuration: An optional network configuration. If not supplied, a default configuration will be used.
        scan_commands: An optional list of scan commands to run against the server. If not supplied, all available
            scan commands will be run.
        scan_commands_extra_arguments: An optional list of extra arguments specific to some scan commands. If not
            supplied, no extra arguments will be set.
    """

    server_location: ServerNetworkLocation

    # If not specified, a default network config will be used
    network_configuration: ServerNetworkConfiguration = field(default=None)  # type: ignore

    # If not specified, run all scan commands by default
    scan_commands: Set[ScanCommand] = field(default_factory=ScanCommandsRepository.get_all_scan_commands)
    scan_commands_extra_arguments: ScanCommandsExtraArguments = field(default_factory=ScanCommandsExtraArguments)

    # Random ID to track the scan
    uuid: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        # If not network config was passed, generate the default one
        if self.network_configuration is None:
            # Official workaround for frozen=True: https://docs.python.org/3/library/dataclasses.html#frozen-instances
            object.__setattr__(
                self,
                "network_configuration",
                ServerNetworkConfiguration.default_for_server_location(self.server_location),
            )

        # Ensure that the extra arguments match the scan commands
        for class_field in fields(self.scan_commands_extra_arguments):
            scan_command = class_field.name
            if (
                getattr(self.scan_commands_extra_arguments, scan_command, None)
                and scan_command not in self.scan_commands
            ):
                raise ValueError(f"Received an extra argument for a scan command that wasn't enabled: {scan_command}")


class CertificateInfoScanAttempt(ScanCommandAttempt[CertificateInfoScanResult]):
    pass


class CipherSuitesScanAttempt(ScanCommandAttempt[CipherSuitesScanResult]):
    pass


class CompressionScanAttempt(ScanCommandAttempt[CompressionScanResult]):
    pass


class EarlyDataScanAttempt(ScanCommandAttempt[EarlyDataScanResult]):
    pass


class OpenSslCcsInjectionScanAttempt(ScanCommandAttempt[OpenSslCcsInjectionScanResult]):
    pass


class FallbackScsvScanAttempt(ScanCommandAttempt[FallbackScsvScanResult]):
    pass


class HeartbleedScanAttempt(ScanCommandAttempt[HeartbleedScanResult]):
    pass


class RobotScanAttempt(ScanCommandAttempt[RobotScanResult]):
    pass


class SessionRenegotiationScanAttempt(ScanCommandAttempt[SessionRenegotiationScanResult]):
    pass


class SessionResumptionSupportScanAttempt(ScanCommandAttempt[SessionResumptionSupportScanResult]):
    pass


class HttpHeadersScanAttempt(ScanCommandAttempt[HttpHeadersScanResult]):
    pass


class SupportedEllipticCurvesScanAttempt(ScanCommandAttempt[SupportedEllipticCurvesScanResult]):
    pass


@dataclass(frozen=True)
class AllScanCommandsAttempts:
    """The result of every scan command supported by SSLyze."""

    certificate_info: CertificateInfoScanAttempt
    ssl_2_0_cipher_suites: CipherSuitesScanAttempt
    ssl_3_0_cipher_suites: CipherSuitesScanAttempt
    tls_1_0_cipher_suites: CipherSuitesScanAttempt
    tls_1_1_cipher_suites: CipherSuitesScanAttempt
    tls_1_2_cipher_suites: CipherSuitesScanAttempt
    tls_1_3_cipher_suites: CipherSuitesScanAttempt
    tls_compression: CompressionScanAttempt
    tls_1_3_early_data: EarlyDataScanAttempt
    openssl_ccs_injection: OpenSslCcsInjectionScanAttempt
    tls_fallback_scsv: FallbackScsvScanAttempt
    heartbleed: HeartbleedScanAttempt
    robot: RobotScanAttempt
    session_renegotiation: SessionRenegotiationScanAttempt
    session_resumption: SessionResumptionSupportScanAttempt
    elliptic_curves: SupportedEllipticCurvesScanAttempt
    http_headers: HttpHeadersScanAttempt


def get_scan_command_attempt_cls(scan_command: ScanCommand) -> Type[ScanCommandAttempt]:
    field_name_to_cls = {cls_field.name: cls_field.type for cls_field in fields(AllScanCommandsAttempts)}
    return field_name_to_cls[scan_command.value]


class ServerConnectivityStatusEnum(str, Enum):
    ERROR = "ERROR"
    COMPLETED = "COMPLETED"


class ServerScanStatusEnum(str, Enum):
    ERROR_NO_CONNECTIVITY = "ERROR_NO_CONNECTIVITY"
    COMPLETED = "COMPLETED"


@dataclass(frozen=True)
class ServerScanResult:
    """The result of scanning a server.

    Attributes:
        uuid
        server_location
        network_configuration
        connectivity_status: Whether SSLyze was able to connect to the server, or not.
        connectivity_error_trace: The connectivity error; only set if SSLyze was NOT able to connect to the server.
        connectivity_result: The result of connectivity testing; only set if SSLyze was able to connect to the server.
        scan_status: Whether SSLyze was able to complete the scan, or not.
        scan_result: The result of the scan; only set if SSLyze was able to complete the scan.
    """

    uuid: UUID
    server_location: ServerNetworkLocation
    network_configuration: ServerNetworkConfiguration

    # First, SSLyze ensures that it is able to to connect to the server
    connectivity_status: ServerConnectivityStatusEnum
    connectivity_error_trace: Optional[TracebackException]
    connectivity_result: Optional[ServerTlsProbingResult]

    # If SSLyze was able to connect then it performs the TLS scan
    scan_status: ServerScanStatusEnum
    scan_result: Optional[AllScanCommandsAttempts]  # Set it the scan_status == COMPLETED
