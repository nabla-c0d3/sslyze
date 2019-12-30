from enum import Enum
from typing import Dict, Type, TYPE_CHECKING

from sslyze.plugins.certificate_info.scan_commands import CertificateInfoImplementation

if TYPE_CHECKING:
    from sslyze.plugins.plugin_base import ScanCommandImplementation


class ScanCommandEnum(Enum):
    CERTIFICATE_INFO = "certinfo"
    COMPRESSION = "compression"

    def _get_implementation_cls(self):
        return _IMPLEMENTATION_CLASSES[self]


_IMPLEMENTATION_CLASSES: Dict[ScanCommandEnum, Type["ScanCommandImplementation"]] = {
    ScanCommandEnum.CERTIFICATE_INFO: CertificateInfoImplementation
}
