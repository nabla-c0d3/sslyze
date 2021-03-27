from dataclasses import dataclass, field
from enum import unique, Enum, auto
from traceback import TracebackException
from typing import Dict, Set

from sslyze.plugins.elliptic_curves_plugin import SupportedEllipticCurvesScanResult

try:
    # Python 3.7
    from typing_extensions import TypedDict
except ModuleNotFoundError:
    # Python 3.8+
    from typing import TypedDict  # type: ignore

from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult, CertificateInfoExtraArguments
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.early_data_plugin import EarlyDataScanResult
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanResult
from sslyze.plugins.heartbleed_plugin import HeartbleedScanResult
from sslyze.plugins.http_headers_plugin import HttpHeadersScanResult
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanResult
from sslyze.plugins.openssl_cipher_suites.implementation import CipherSuitesScanResult
from sslyze.plugins.robot.implementation import RobotScanResult
from sslyze.plugins.scan_commands import ScanCommandType
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanResult
from sslyze.plugins.session_resumption.implementation import (
    SessionResumptionSupportScanResult,
    SessionResumptionSupportExtraArguments,
)
from sslyze.server_connectivity import ServerConnectivityInfo


@unique
class ScanCommandErrorReasonEnum(Enum):
    BUG_IN_SSLYZE = auto()
    CLIENT_CERTIFICATE_NEEDED = auto()
    CONNECTIVITY_ISSUE = auto()
    WRONG_USAGE = auto()


@dataclass(frozen=True)
class ScanCommandError:
    """An error that prevented a specific scan command ran against a specific server from completing.
    ."""

    reason: ScanCommandErrorReasonEnum
    exception_trace: TracebackException


class ScanCommandExtraArgumentsDict(TypedDict, total=False):
    # Field is present if extra arguments were provided for the corresponding scan command
    certificate_info: CertificateInfoExtraArguments
    session_resumption: SessionResumptionSupportExtraArguments


@dataclass(frozen=True)
class ServerScanRequest:
    """A request to scan a specific server with the supplied scan commands.
    """

    server_info: ServerConnectivityInfo
    scan_commands: Set[ScanCommandType]
    scan_commands_extra_arguments: ScanCommandExtraArgumentsDict = field(default_factory=dict)  # type: ignore

    def __post_init__(self) -> None:
        """"Validate that the extra arguments match the scan commands.
        """
        if not self.scan_commands_extra_arguments:
            return

        for scan_command in self.scan_commands_extra_arguments:
            if scan_command not in self.scan_commands:
                raise ValueError(f"Received an extra argument for a scan command that wasn't enabled: {scan_command}")


# TypedDict for simpler/matching JSON output and makes fetching a field easier
class ScanCommandResultsDict(TypedDict, total=False):
    """A dictionary of results for every scan command that was scheduled against a specific server.
    """

    # Field is present if the corresponding scan command was scheduled and was run successfully
    certificate_info: CertificateInfoScanResult
    ssl_2_0_cipher_suites: CipherSuitesScanResult
    ssl_3_0_cipher_suites: CipherSuitesScanResult
    tls_1_0_cipher_suites: CipherSuitesScanResult
    tls_1_1_cipher_suites: CipherSuitesScanResult
    tls_1_2_cipher_suites: CipherSuitesScanResult
    tls_1_3_cipher_suites: CipherSuitesScanResult
    tls_compression: CompressionScanResult
    tls_1_3_early_data: EarlyDataScanResult
    openssl_ccs_injection: OpenSslCcsInjectionScanResult
    tls_fallback_scsv: FallbackScsvScanResult
    heartbleed: HeartbleedScanResult
    robot: RobotScanResult
    session_renegotiation: SessionRenegotiationScanResult
    session_resumption: SessionResumptionSupportScanResult
    http_headers: HttpHeadersScanResult
    elliptic_curves: SupportedEllipticCurvesScanResult


ScanCommandErrorsDict = Dict[ScanCommandType, ScanCommandError]


@dataclass(frozen=True)
class ServerScanResult:
    """The result of a ServerScanRequest that was completed by a Scanner.
    """

    scan_commands_results: ScanCommandResultsDict
    scan_commands_errors: ScanCommandErrorsDict

    # What was passed in the corresponding ServerScanRequest
    server_info: ServerConnectivityInfo
    scan_commands: Set[ScanCommandType]
    scan_commands_extra_arguments: ScanCommandExtraArgumentsDict
