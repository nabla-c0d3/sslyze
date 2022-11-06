from dataclasses import dataclass
from hashlib import sha256
from typing import List, cast

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import (
    ExtensionOID,
    DNSName,
    ExtensionNotFound,
    NameOID,
    DuplicateExtension,
    IPAddress,
    Certificate,
    SubjectAlternativeName,
    Name,
)


@dataclass(frozen=True)
class SubjectAlternativeNameExtension:
    dns_names: List[str]
    ip_addresses: List[str]


def parse_subject_alternative_name_extension(certificate: Certificate) -> SubjectAlternativeNameExtension:
    try:
        san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_ext_value = cast(SubjectAlternativeName, san_ext.value)
    except ExtensionNotFound:
        return SubjectAlternativeNameExtension(dns_names=[], ip_addresses=[])
    except DuplicateExtension:
        # Fix for https://github.com/nabla-c0d3/sslyze/issues/420
        # Not sure how browsers behave in this case but having a duplicate extension makes the certificate invalid
        # so we just return no SANs (likely to make hostname validation fail, which is fine)
        return SubjectAlternativeNameExtension(dns_names=[], ip_addresses=[])

    dns_names = []
    ip_addresses = []
    for san_value in san_ext_value:
        if isinstance(san_value, IPAddress):
            ip_addresses.append(str(san_value.value))
        elif isinstance(san_value, DNSName):
            dns_names.append(san_value.value)
        else:
            pass

    return SubjectAlternativeNameExtension(dns_names=dns_names, ip_addresses=ip_addresses)


def get_common_names(name_field: Name) -> List[str]:
    return [cn.value for cn in name_field.get_attributes_for_oid(NameOID.COMMON_NAME)]  # type: ignore


def get_public_key_sha256(certificate: Certificate) -> bytes:
    pub_bytes = certificate.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    digest = sha256(pub_bytes).digest()
    return digest
