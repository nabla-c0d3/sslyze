from enum import Enum
from typing import Dict, Type, TYPE_CHECKING, Set

from sslyze.plugins.elliptic_curves_plugin import SupportedEllipticCurvesImplementation


from sslyze.plugins.certificate_info.implementation import CertificateInfoImplementation
from sslyze.plugins.compression_plugin import CompressionImplementation
from sslyze.plugins.early_data_plugin import EarlyDataImplementation
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvImplementation
from sslyze.plugins.heartbleed_plugin import HeartbleedImplementation
from sslyze.plugins.http_headers_plugin import HttpHeadersImplementation
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionImplementation
from sslyze.plugins.openssl_cipher_suites.implementation import (
    Sslv20ScanImplementation,
    Sslv30ScanImplementation,
    Tlsv10ScanImplementation,
    Tlsv13ScanImplementation,
    Tlsv12ScanImplementation,
    Tlsv11ScanImplementation,
)
from sslyze.plugins.robot.implementation import RobotImplementation
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationImplementation
from sslyze.plugins.session_resumption.implementation import SessionResumptionSupportImplementation

if TYPE_CHECKING:
    from sslyze.plugins.plugin_base import ScanCommandImplementation  # noqa: F401


class ScanCommand(str, Enum):
    CERTIFICATE_INFO = "certificate_info"
    SESSION_RESUMPTION = "session_resumption"
    SSL_2_0_CIPHER_SUITES = "ssl_2_0_cipher_suites"
    SSL_3_0_CIPHER_SUITES = "ssl_3_0_cipher_suites"
    TLS_1_0_CIPHER_SUITES = "tls_1_0_cipher_suites"
    TLS_1_1_CIPHER_SUITES = "tls_1_1_cipher_suites"
    TLS_1_2_CIPHER_SUITES = "tls_1_2_cipher_suites"
    TLS_1_3_CIPHER_SUITES = "tls_1_3_cipher_suites"
    TLS_COMPRESSION = "tls_compression"
    TLS_1_3_EARLY_DATA = "tls_1_3_early_data"
    OPENSSL_CCS_INJECTION = "openssl_ccs_injection"
    TLS_FALLBACK_SCSV = "tls_fallback_scsv"
    HEARTBLEED = "heartbleed"
    ROBOT = "robot"
    SESSION_RENEGOTIATION = "session_renegotiation"
    HTTP_HEADERS = "http_headers"
    ELLIPTIC_CURVES = "elliptic_curves"


class ScanCommandsRepository:
    @staticmethod
    def get_implementation_cls(scan_command: ScanCommand) -> Type["ScanCommandImplementation"]:
        return _IMPLEMENTATION_CLASSES[scan_command]

    @staticmethod
    def get_all_scan_commands() -> Set[ScanCommand]:
        return set(_IMPLEMENTATION_CLASSES.keys())


_IMPLEMENTATION_CLASSES: Dict[ScanCommand, Type["ScanCommandImplementation"]] = {
    ScanCommand.CERTIFICATE_INFO: CertificateInfoImplementation,
    ScanCommand.SESSION_RESUMPTION: SessionResumptionSupportImplementation,
    ScanCommand.SSL_2_0_CIPHER_SUITES: Sslv20ScanImplementation,
    ScanCommand.SSL_3_0_CIPHER_SUITES: Sslv30ScanImplementation,
    ScanCommand.TLS_1_0_CIPHER_SUITES: Tlsv10ScanImplementation,
    ScanCommand.TLS_1_1_CIPHER_SUITES: Tlsv11ScanImplementation,
    ScanCommand.TLS_1_2_CIPHER_SUITES: Tlsv12ScanImplementation,
    ScanCommand.TLS_1_3_CIPHER_SUITES: Tlsv13ScanImplementation,
    ScanCommand.TLS_COMPRESSION: CompressionImplementation,
    ScanCommand.TLS_1_3_EARLY_DATA: EarlyDataImplementation,
    ScanCommand.OPENSSL_CCS_INJECTION: OpenSslCcsInjectionImplementation,
    ScanCommand.TLS_FALLBACK_SCSV: FallbackScsvImplementation,
    ScanCommand.HEARTBLEED: HeartbleedImplementation,
    ScanCommand.ROBOT: RobotImplementation,
    ScanCommand.SESSION_RENEGOTIATION: SessionRenegotiationImplementation,
    ScanCommand.HTTP_HEADERS: HttpHeadersImplementation,
    ScanCommand.ELLIPTIC_CURVES: SupportedEllipticCurvesImplementation,
}
