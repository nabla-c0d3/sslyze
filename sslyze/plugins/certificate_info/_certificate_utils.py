from hashlib import sha256
from typing import List, cast

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import DNSName, ExtensionNotFound, IPAddress, NameOID
from cryptography.x509.extensions import DuplicateExtension  # type: ignore
from cryptography.x509.oid import ExtensionOID


def extract_dns_subject_alternative_names(certificate: x509.Certificate) -> List[str]:
    """Retrieve all the DNS entries of the Subject Alternative Name extension.
    """
    subj_alt_names: List[str] = []
    try:
        san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_ext_value = cast(x509.SubjectAlternativeName, san_ext.value)
        for san_value in san_ext_value:
            if isinstance(san_value, IPAddress):
                subj_alt_names.append(str(san_value.value))
            elif isinstance(san_value, DNSName):
                subj_alt_names.append(san_value.value)
            else:
                pass
    except ExtensionNotFound:
        pass
    except DuplicateExtension:
        # Fix for https://github.com/nabla-c0d3/sslyze/issues/420
        # Not sure how browsers behave in this case but having a duplicate extension makes the certificate invalid
        # so we just return no SANs (likely to make hostname validation fail, which is fine)
        pass

    return subj_alt_names


def get_common_names(name_field: x509.Name) -> List[str]:
    return [cn.value for cn in name_field.get_attributes_for_oid(NameOID.COMMON_NAME)]


def get_public_key_sha256(certificate: x509.Certificate) -> bytes:
    pub_bytes = certificate.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    digest = sha256(pub_bytes).digest()
    return digest
