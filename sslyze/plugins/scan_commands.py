from typing import Dict, Type, TYPE_CHECKING, Set

try:
    # Python 3.7
    from typing_extensions import Literal
except ModuleNotFoundError:
    # Python 3.8+
    from typing import Literal  # type: ignore

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
from sslyze.plugins.session_resumption.implementation import (
    SessionResumptionRateImplementation,
    SessionResumptionSupportImplementation,
)

if TYPE_CHECKING:
    from sslyze.plugins.plugin_base import ScanCommandImplementation  # noqa: F401


ScanCommandType = Literal[
    "certificate_info",
    "ssl_2_0_cipher_suites",
    "ssl_3_0_cipher_suites",
    "tls_1_0_cipher_suites",
    "tls_1_1_cipher_suites",
    "tls_1_1_cipher_suites",
    "tls_1_2_cipher_suites",
    "tls_1_3_cipher_suites",
    "tls_compression",
    "tls_1_3_early_data",
    "openssl_ccs_injection",
    "tls_fallback_scsv",
    "heartbleed",
    "robot",
    "session_renegotiation",
    "session_resumption",
    "session_resumption_rate",
    "http_headers",
]


# Almost like a re-implementation of an enum
class ScanCommand:
    """The list of all scan commands supported by SSLyze.
    """

    CERTIFICATE_INFO: Literal["certificate_info"] = "certificate_info"

    SSL_2_0_CIPHER_SUITES: Literal["ssl_2_0_cipher_suites"] = "ssl_2_0_cipher_suites"
    SSL_3_0_CIPHER_SUITES: Literal["ssl_3_0_cipher_suites"] = "ssl_3_0_cipher_suites"
    TLS_1_0_CIPHER_SUITES: Literal["tls_1_0_cipher_suites"] = "tls_1_0_cipher_suites"
    TLS_1_1_CIPHER_SUITES: Literal["tls_1_1_cipher_suites"] = "tls_1_1_cipher_suites"
    TLS_1_2_CIPHER_SUITES: Literal["tls_1_2_cipher_suites"] = "tls_1_2_cipher_suites"
    TLS_1_3_CIPHER_SUITES: Literal["tls_1_3_cipher_suites"] = "tls_1_3_cipher_suites"

    TLS_COMPRESSION: Literal["tls_compression"] = "tls_compression"

    TLS_1_3_EARLY_DATA: Literal["tls_1_3_early_data"] = "tls_1_3_early_data"

    OPENSSL_CCS_INJECTION: Literal["openssl_ccs_injection"] = "openssl_ccs_injection"

    TLS_FALLBACK_SCSV: Literal["tls_fallback_scsv"] = "tls_fallback_scsv"

    HEARTBLEED: Literal["heartbleed"] = "heartbleed"

    ROBOT: Literal["robot"] = "robot"

    SESSION_RENEGOTIATION: Literal["session_renegotiation"] = "session_renegotiation"

    SESSION_RESUMPTION: Literal["session_resumption"] = "session_resumption"
    SESSION_RESUMPTION_RATE: Literal["session_resumption_rate"] = "session_resumption_rate"

    HTTP_HEADERS: Literal["http_headers"] = "http_headers"


class ScanCommandsRepository:
    @staticmethod
    def get_implementation_cls(scan_command: ScanCommandType) -> Type["ScanCommandImplementation"]:
        return _IMPLEMENTATION_CLASSES[scan_command]

    @staticmethod
    def get_all_scan_commands() -> Set[ScanCommandType]:
        return set(_IMPLEMENTATION_CLASSES.keys())


_IMPLEMENTATION_CLASSES: Dict[ScanCommandType, Type["ScanCommandImplementation"]] = {
    ScanCommand.CERTIFICATE_INFO: CertificateInfoImplementation,
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
    ScanCommand.SESSION_RESUMPTION: SessionResumptionSupportImplementation,
    ScanCommand.SESSION_RESUMPTION_RATE: SessionResumptionRateImplementation,
    ScanCommand.HTTP_HEADERS: HttpHeadersImplementation,
}
