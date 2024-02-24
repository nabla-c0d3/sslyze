from dataclasses import dataclass
import datetime
from pathlib import Path

from cryptography.x509 import Certificate
from cryptography.x509 import ExtensionNotFound, CertificatePolicies
from cryptography.x509 import ObjectIdentifier
from cryptography.x509 import ExtensionOID
from typing import List, cast
from typing import Optional
from cryptography.x509 import load_pem_x509_certificates, DNSName, load_pem_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError


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
        validation_error: The error returned by the cryptography module's validation function; None if validation was
            successful.
        was_validation_successful: Whether the certificate chain is trusted when using supplied the trust_stores.
    """

    trust_store: "TrustStore"
    verified_certificate_chain: Optional[List[Certificate]]
    validation_error: Optional[str]

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

        self._x509_store = Store(load_pem_x509_certificates(self.path.read_text().encode("ascii")))

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

    def verify_certificate_chain(
        self,
        certificate_chain_as_pem: List[str],
        server_hostname: str,
        validation_time: Optional[datetime.datetime] = None,
    ) -> PathValidationResult:
        final_validation_time = validation_time or datetime.datetime.now()
        builder = PolicyBuilder().store(self._x509_store)
        builder = builder.time(final_validation_time)

        verifier = builder.build_server_verifier(DNSName(server_hostname))

        leaf_cert = load_pem_x509_certificate(certificate_chain_as_pem[0].encode("ascii"))
        intermediate_certs = [load_pem_x509_certificate(pem.encode("ascii")) for pem in certificate_chain_as_pem[1:]]

        try:
            verified_chain = verifier.verify(leaf_cert, intermediate_certs)
            error_message = None

        except VerificationError as e:
            error_message = e.args[0]
            verified_chain = None

        path_result = PathValidationResult(
            trust_store=self, verified_certificate_chain=verified_chain, validation_error=error_message
        )
        return path_result
