# flake8: noqa

# Classes for configuring the servers to scan
from sslyze.server_setting import (
    ServerNetworkLocation,
    ConnectionTypeEnum,
    HttpProxySettings,
    ClientAuthenticationCredentials,
    ServerNetworkConfiguration,
)
from sslyze.connection_helpers.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum
from nassl.ssl_client import OpenSslFileTypeEnum


# Classes for testing connectivity with the servers
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    TlsVersionEnum,
    ServerTlsProbingResult,
)

# Classes for setting up scan commands and extra arguments
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.plugins.certificate_info.implementation import CertificateInfoExtraArgument

# Classes for scanning the servers
from sslyze.scanner.models import (
    ServerScanRequest,
    ScanCommandsExtraArguments,
    ServerScanResult,
    ServerConnectivityStatusEnum,
    ServerScanStatusEnum,
    AllScanCommandsAttempts,
)
from sslyze.scanner.scan_command_attempt import (
    ScanCommandAttempt,
    ScanCommandAttemptStatusEnum,
    ScanCommandErrorReasonEnum,
)
from sslyze.scanner.scanner import Scanner
from sslyze.errors import ServerHostnameCouldNotBeResolved


# Classes with the scan results
from sslyze.plugins.plugin_base import ScanCommandResult

# Certificate Info
from sslyze.plugins.certificate_info.implementation import (
    CertificateInfoScanResult,
    CertificateDeploymentAnalysisResult,
)
from sslyze.plugins.certificate_info._cert_chain_analyzer import PathValidationResult
from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore

# Cipher Suites
from sslyze.plugins.openssl_cipher_suites.implementation import CipherSuitesScanResult
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    CipherSuiteAcceptedByServer,
    CipherSuiteRejectedByServer,
)
from nassl.ephemeral_key_info import EphemeralKeyInfo
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite

from sslyze.plugins.robot.implementation import RobotScanResult, RobotScanResultEnum

from sslyze.plugins.session_resumption.implementation import (
    SessionResumptionSupportScanResult,
    TlsResumptionSupportEnum,
    SessionResumptionSupportExtraArgument,
)
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.early_data_plugin import EarlyDataScanResult
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanResult
from sslyze.plugins.heartbleed_plugin import HeartbleedScanResult

# HTTP Headers
from sslyze.plugins.http_headers_plugin import (
    HttpHeadersScanResult,
    StrictTransportSecurityHeader,
    ExpectCtHeader,
)


from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanResult
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanResult
from sslyze.plugins.elliptic_curves_plugin import SupportedEllipticCurvesScanResult, EllipticCurve

from sslyze.json.json_output import SslyzeOutputAsJson, ServerScanResultAsJson
