# flake8: noqa

# Classes for configuring the servers to scan
from sslyze.server_setting import (
    ServerNetworkLocationViaDirectConnection,
    HttpProxySettings,
    ServerNetworkLocationViaHttpProxy,
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
    ServerConnectivityInfo,
    ServerConnectivityTester,
)


# Classes for setting up scan commands and extra arguments
from sslyze.plugins.scan_commands import ScanCommand, ScanCommandType
from sslyze.plugins.certificate_info.implementation import CertificateInfoExtraArguments


# Classes for scanning the servers
from sslyze.scanner import (
    ScanCommandError,
    ScanCommandErrorReasonEnum,
    ScanCommandExtraArgumentsDict,
    ScanCommandResultsDict,
    ScanCommandErrorsDict,
    ServerScanRequest,
    ServerScanResult,
    Scanner,
)
