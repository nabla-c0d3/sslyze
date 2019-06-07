import ssl
from typing import List

import cryptography
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import DNSName, ExtensionNotFound, ExtensionOID, NameOID

from base64 import b64encode
from hashlib import sha256


class CertificateUtils:
    """Various utility methods for handling X509 certificates as parsed by the cryptography module.
    """

    @staticmethod
    def get_common_names(name_field: cryptography.x509.Name) -> List[str]:
        return [cn.value for cn in name_field.get_attributes_for_oid(NameOID.COMMON_NAME)]

    @staticmethod
    def get_dns_subject_alternative_names(certificate: cryptography.x509.Certificate) -> List[str]:
        """Retrieve all the DNS entries of the Subject Alternative Name extension.
        """
        subj_alt_names: List[str] = []
        try:
            san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            subj_alt_names = san_ext.value.get_values_for_type(DNSName)
        except ExtensionNotFound:
            pass
        return subj_alt_names

    @classmethod
    def matches_hostname(cls, certificate: cryptography.x509.Certificate, hostname: str) -> None:
        """Verify that the certificate was issued for the given hostname.

        Raises:
            CertificateError: If the certificate was not issued for the supplied hostname.
        """
        # Extract the names from the certificate to create the properly-formatted dictionary
        certificate_names = {
            "subject": (tuple([("commonName", name) for name in cls.get_common_names(certificate.subject)]),),
            "subjectAltName": tuple([("DNS", name) for name in cls.get_dns_subject_alternative_names(certificate)]),
        }
        # CertificateError is raised on failure
        ssl.match_hostname(certificate_names, hostname)  # type: ignore

    @classmethod
    def get_name_as_short_text(cls, name_field: cryptography.x509.Name) -> str:
        """Convert a name field returned by the cryptography module to a string suitable for displaying it to the user.
        """
        # Name_field is supposed to be a Subject or an Issuer; print the CN if there is one
        common_names = cls.get_common_names(name_field)
        if common_names:
            # We don't support certs with multiple CNs
            return common_names[0]
        else:
            # Otherwise show the whole field
            return cls.get_name_as_text(name_field)

    @classmethod
    def get_name_as_text(cls, name_field: cryptography.x509.Name) -> str:
        return ", ".join(["{}={}".format(attr.oid._name, attr.value) for attr in name_field])

    @staticmethod
    def get_public_key_sha256(certificate: cryptography.x509.Certificate) -> bytes:
        pub_bytes = certificate.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
        digest = sha256(pub_bytes).digest()
        return digest

    @classmethod
    def get_hpkp_pin(cls, certificate: cryptography.x509.Certificate) -> str:
        """Generate the HTTP Public Key Pinning hash (RFC 7469) for the given certificate.
        """
        return b64encode(cls.get_public_key_sha256(certificate)).decode("utf-8")

    @staticmethod
    def get_public_key_type(certificate: cryptography.x509.Certificate) -> str:
        public_key = certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return "EllipticCurve"
        else:
            raise ValueError("Unexpected key algorithm")
