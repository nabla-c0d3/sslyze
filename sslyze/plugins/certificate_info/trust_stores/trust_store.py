from dataclasses import dataclass
from pathlib import Path

from OpenSSL import crypto
from cryptography.x509 import Certificate
from cryptography.x509 import ExtensionNotFound, CertificatePolicies
from cryptography.x509 import ObjectIdentifier
from cryptography.x509 import ExtensionOID
from typing import List, cast
from typing import Optional


@dataclass(frozen=True)
class PathValidationResult:
    """The result of trying to validate a server's certificate chain using a specific trust store.

    Attributes:
        trust_store: The trust store used for validation.
        verified_certificate_chain: The verified certificate chain returned by OpenSSL.
            Index 0 is the leaf certificate and the last element is the anchor/CA certificate from the trust store.
            Will be None if the validation failed or the verified chain could not be built.
            Each certificate is parsed using the cryptography module; documentation is available at
            https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object.
        openssl_error_string: The result string returned by OpenSSL's validation function; None if validation was
            successful.
        was_validation_successful: Whether the certificate chain is trusted when using supplied the trust_stores.
    """

    trust_store: "TrustStore"
    verified_certificate_chain: Optional[List[Certificate]]
    openssl_error_string: Optional[str]

    @property
    def was_validation_successful(self) -> bool:
        return True if self.verified_certificate_chain else False


class TrustStore:
    """A set of root certificates to be used for certificate validation.

    Attributes:
        path: The path on the local system to the PEM-formatted file containing the root certificates.
        name: The human-readable name of the trust store (such as "Mozilla").
        version: The human-readable version or date of the trust store (such as "09/2016").
    """

    def __init__(self, path: Path, name: str, version: str, ev_oids: Optional[List[ObjectIdentifier]] = None) -> None:
        self.path = path
        self.name = name
        self.version = version
        self.ev_oids = ev_oids

        self._x509_store = crypto.X509Store()
        self._x509_store.load_locations(cafile=self.path)

    def is_certificate_extended_validation(self, certificate: Certificate) -> bool:
        """Is the supplied server certificate EV?"""
        if not self.ev_oids:
            raise ValueError("No EV OIDs supplied for {} store - cannot detect EV certificates".format(self.name))

        try:
            cert_policies_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        except ExtensionNotFound:
            return False

        cert_policies_value = cast(CertificatePolicies, cert_policies_ext.value)
        for policy in cert_policies_value:
            if policy.policy_identifier in self.ev_oids:
                return True
        return False

    def verify_certificate_chain(self, certificate_chain_as_pem: List[str]) -> PathValidationResult:
        certificate = crypto.load_certificate(
            buffer=certificate_chain_as_pem[0].encode("ascii"), type=crypto.FILETYPE_PEM
        )
        chain = [
            crypto.load_certificate(buffer=cert.encode("ascii"), type=crypto.FILETYPE_PEM)
            for cert in certificate_chain_as_pem[1::]
        ]
        x509_store_ctx = crypto.X509StoreContext(store=self._x509_store, certificate=certificate, chain=chain)

        verified_chain: Optional[List[Certificate]]
        error_message: Optional[str]
        try:
            verified_chain_as_x509s = x509_store_ctx.get_verified_chain()
            verified_chain = [x509.to_cryptography() for x509 in verified_chain_as_x509s]
            error_message = None
        except crypto.X509StoreContextError as exc:
            verified_chain = None
            error_message = exc.args[0]

        return PathValidationResult(
            trust_store=self, verified_certificate_chain=verified_chain, openssl_error_string=error_message
        )
