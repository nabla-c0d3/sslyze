from enum import Enum, unique
from typing import Dict, Type, TYPE_CHECKING

from sslyze.plugins.certificate_info.core import CertificateInfoImplementation
from sslyze.plugins.compression_plugin import CompressionImplementation
from sslyze.plugins.early_data_plugin import EarlyDataImplementation
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvImplementation
from sslyze.plugins.heartbleed_plugin import HeartbleedImplementation
from sslyze.plugins.http_headers_plugin import HttpHeadersImplementation
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionImplementation
from sslyze.plugins.openssl_cipher_suites.scan_commands import (
    Sslv20ScanImplementation,
    Sslv30ScanImplementation,
    Tlsv10ScanImplementation,
    Tlsv13ScanImplementation,
    Tlsv12ScanImplementation,
    Tlsv11ScanImplementation,
)
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationImplementation
from sslyze.plugins.session_resumption.core import (
    SessionResumptionRateImplementation,
    SessionResumptionSupportImplementation,
)

if TYPE_CHECKING:
    from sslyze.plugins.plugin_base import ScanCommandImplementation  # noqa: F401


@unique
class ScanCommandEnum(Enum):
    CERTIFICATE_INFO = "certinfo"

    SSL_2_0_CIPHER_SUITES = "sslv2"
    SSL_3_0_CIPHER_SUITES = "sslv3"
    TLS_1_0_CIPHER_SUITES = "tlsv1_0"
    TLS_1_1_CIPHER_SUITES = "tlsv1_1"
    TLS_1_2_CIPHER_SUITES = "tlsv1_2"
    TLS_1_3_CIPHER_SUITES = "tlsv1_3"

    TLS_COMPRESSION = "compression"

    TLS_1_3_EARLY_DATA = "early_data"

    OPENSSL_CCS_INJECTION = "openssl_ccs"

    TLS_FALLBACK_SCSV = "fallback"

    HEARTBLEED = "heartbleed"


    SESSION_RENEGOTIATION = "reneg"

    SESSION_RESUMPTION = "resum"
    SESSION_RESUMPTION_RATE = "resum_rate"

    HTTP_HEADERS = "http_headers"

    def _get_implementation_cls(self) -> Type["ScanCommandImplementation"]:
        return _IMPLEMENTATION_CLASSES[self]


_IMPLEMENTATION_CLASSES: Dict[ScanCommandEnum, Type["ScanCommandImplementation"]] = {
    ScanCommandEnum.CERTIFICATE_INFO: CertificateInfoImplementation,
    ScanCommandEnum.SSL_2_0_CIPHER_SUITES: Sslv20ScanImplementation,
    ScanCommandEnum.SSL_3_0_CIPHER_SUITES: Sslv30ScanImplementation,
    ScanCommandEnum.TLS_1_0_CIPHER_SUITES: Tlsv10ScanImplementation,
    ScanCommandEnum.TLS_1_1_CIPHER_SUITES: Tlsv11ScanImplementation,
    ScanCommandEnum.TLS_1_2_CIPHER_SUITES: Tlsv12ScanImplementation,
    ScanCommandEnum.TLS_1_3_CIPHER_SUITES: Tlsv13ScanImplementation,
    ScanCommandEnum.TLS_COMPRESSION: CompressionImplementation,
    ScanCommandEnum.TLS_1_3_EARLY_DATA: EarlyDataImplementation,
    ScanCommandEnum.OPENSSL_CCS_INJECTION: OpenSslCcsInjectionImplementation,
    ScanCommandEnum.TLS_FALLBACK_SCSV: FallbackScsvImplementation,
    ScanCommandEnum.HEARTBLEED: HeartbleedImplementation,
    ScanCommandEnum.SESSION_RENEGOTIATION: SessionRenegotiationImplementation,
    ScanCommandEnum.SESSION_RESUMPTION: SessionResumptionSupportImplementation,
    ScanCommandEnum.SESSION_RESUMPTION_RATE: SessionResumptionRateImplementation,
    ScanCommandEnum.HTTP_HEADERS: HttpHeadersImplementation,
}
