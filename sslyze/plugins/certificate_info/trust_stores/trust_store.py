from dataclasses import dataclass
from pathlib import Path

from cryptography.x509.base import Certificate
from cryptography.x509.extensions import ExtensionNotFound, CertificatePolicies
from cryptography.x509.oid import ObjectIdentifier
from cryptography.x509.oid import ExtensionOID
from typing import List, cast
from typing import Optional


@dataclass(frozen=True)
class TrustStore:
    """A set of root certificates to be used for certificate validation.

    Attributes:
        path: The path on the local system to the PEM-formatted file containing the root certificates.
        name: The human-readable name of the trust store (such as "Mozilla").
        version: The human-readable version or date of the trust store (such as "09/2016").
    """

    path: Path
    name: str
    version: str
    ev_oids: Optional[List[ObjectIdentifier]] = None

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
