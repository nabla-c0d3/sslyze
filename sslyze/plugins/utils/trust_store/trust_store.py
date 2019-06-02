from pathlib import Path

from cryptography.x509.base import Certificate
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ObjectIdentifier
from cryptography.x509.oid import ExtensionOID
from typing import Dict, Any
from typing import List
from typing import Optional


class TrustStore:
    """A set of root certificates to be used for certificate validation.

    By default, SSLyze packages the following trust stores: Mozilla, Microsoft, Apple, Android and Java.

    Attributes:
        path (Path): The path to the PEM-formatted file containing the root certificates.
        name (str): The human-readable name of the trust store (such as "Mozilla").
        version (str): The human-readable version or date of the trust store (such as "09/2016").
    """

    def __init__(self, path: Path, name: str, version: str, ev_oids: Optional[List[str]] = None) -> None:
        self.path = path
        self.name = name
        self.version = version

        # Used for pickling
        self.__ev_oids_as_str = ev_oids
        self.ev_oids: List[ObjectIdentifier] = []
        self.__parse_ev_oids()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TrustStore) and self.path == other.path and self.ev_oids == other.ev_oids:
            return True
        return False

    def __parse_ev_oids(self) -> None:
        if self.__ev_oids_as_str:
            self.ev_oids = [ObjectIdentifier(oid) for oid in self.__ev_oids_as_str]

    def __getstate__(self) -> Dict[str, Any]:
        pickable_dict = self.__dict__.copy()
        # Remove non-pickable entries
        pickable_dict['ev_oids'] = []
        return pickable_dict

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        # Manually restore non-pickable entries
        self.__parse_ev_oids()

    def is_extended_validation(self, certificate: Certificate) -> bool:
        """Is the supplied server certificate EV?
        """
        if not self.ev_oids:
            raise ValueError('No EV OIDs supplied for {} store - cannot detect EV certificates'.format(self.name))

        try:
            cert_policies_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        except ExtensionNotFound:
            return False

        for policy in cert_policies_ext.value:
            if policy.policy_identifier in self.ev_oids:
                return True
        return False
