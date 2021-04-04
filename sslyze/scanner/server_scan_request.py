from dataclasses import dataclass, fields, field
from enum import Enum
from traceback import TracebackException
from typing import Set, Optional, List

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
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanResult
from sslyze.plugins.session_resumption.implementation import (
    SessionResumptionSupportScanResult,
    SessionResumptionSupportExtraArgument,
)
from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class ScanCommandsExtraArguments:
    # Field is present if extra arguments were provided for the corresponding scan command
    certificate_info: Optional[CertificateInfoExtraArgument] = None
    session_resumption: Optional[SessionResumptionSupportExtraArgument] = None


@dataclass(frozen=True)
class ServerScanRequest:
    """A request to scan a specific server with the supplied scan commands.
    """

    server_info: ServerConnectivityInfo
    scan_commands: Set[ScanCommand]
    scan_commands_extra_arguments: ScanCommandsExtraArguments = field(default_factory=ScanCommandsExtraArguments)

    def __post_init__(self) -> None:
        # Ensure that the extra arguments match the scan commands
        for class_field in fields(self.scan_commands_extra_arguments):
            scan_command = class_field.name
            if (
                getattr(self.scan_commands_extra_arguments, scan_command, None)
                and scan_command not in self.scan_commands
            ):
                raise ValueError(f"Received an extra argument for a scan command that wasn't enabled: {scan_command}")


@dataclass(frozen=True)
class ScanCommandsResults:
    # Field is present if the corresponding scan command was scheduled and was run successfully
    certificate_info: Optional[CertificateInfoScanResult] = None
    ssl_2_0_cipher_suites: Optional[CipherSuitesScanResult] = None
    ssl_3_0_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_1_0_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_1_1_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_1_2_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_1_3_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_compression: Optional[CompressionScanResult] = None
    tls_1_3_early_data: Optional[EarlyDataScanResult] = None
    openssl_ccs_injection: Optional[OpenSslCcsInjectionScanResult] = None
    tls_fallback_scsv: Optional[FallbackScsvScanResult] = None
    heartbleed: Optional[HeartbleedScanResult] = None
    robot: Optional[RobotScanResult] = None
    session_renegotiation: Optional[SessionRenegotiationScanResult] = None
    session_resumption: Optional[SessionResumptionSupportScanResult] = None
    http_headers: Optional[HttpHeadersScanResult] = None
    elliptic_curves: Optional[SupportedEllipticCurvesScanResult] = None

    def scan_commands_with_result(self) -> Set[ScanCommand]:
        scan_commands_with_result = set()
        for class_field in fields(self):
            scan_command = ScanCommand(class_field.name)
            if getattr(self, scan_command, None):
                scan_commands_with_result.add(scan_command)
        return scan_commands_with_result


class ScanCommandErrorReasonEnum(str, Enum):
    BUG_IN_SSLYZE = "BUG_IN_SSLYZE"
    CLIENT_CERTIFICATE_NEEDED = "CLIENT_CERTIFICATE_NEEDED"
    CONNECTIVITY_ISSUE = "CONNECTIVITY_ISSUE"
    WRONG_USAGE = "WRONG_USAGE"


@dataclass(frozen=True)
class ScanCommandError:
    """An error that prevented a specific scan command ran against a specific server from completing.
    ."""

    scan_command: ScanCommand
    reason: ScanCommandErrorReasonEnum
    exception_trace: TracebackException


@dataclass(frozen=True)
class ServerScanResult:
    """The result of a ServerScanRequest that was completed by a Scanner.
    """

    # What was passed in the corresponding ServerScanRequest
    server_info: ServerConnectivityInfo
    scan_commands: Set[ScanCommand]
    scan_commands_extra_arguments: ScanCommandsExtraArguments

    scan_commands_results: ScanCommandsResults
    scan_commands_errors: List[ScanCommandError]  # Empty if no errors occurred

    def __post_init__(self) -> None:
        # Ensure that the extra arguments match the scan commands
        for class_field in fields(self.scan_commands_extra_arguments):
            scan_command = class_field.name
            if (
                getattr(self.scan_commands_extra_arguments, scan_command, None)
                and scan_command not in self.scan_commands
            ):
                raise ValueError(f"Received an extra argument for a scan command that wasn't enabled: {scan_command}")

        # Ensure that all requested scan commands returned either a result or an error
        scan_commands_with_results_or_errors = set()
        for class_field in fields(self.scan_commands_results):
            scan_command = class_field.name
            if getattr(self.scan_commands_results, scan_command, None):
                scan_commands_with_results_or_errors.add(scan_command)

        for scan_command in [error.scan_command for error in self.scan_commands_errors]:
            scan_commands_with_results_or_errors.add(scan_command)

        missing_scan_commands = self.scan_commands.difference(scan_commands_with_results_or_errors)
        if missing_scan_commands:
            raise ValueError(f"Missing error or result for scan commands: {missing_scan_commands}")
