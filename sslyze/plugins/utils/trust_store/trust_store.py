import io
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import Certificate
from cryptography.x509.name import Name
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
        path (str): The path to the PEM-formatted file containing the root certificates.
        name (str): The human-readable name of the trust store (such as "Mozilla").
        version (str): The human-readable version or date of the trust store (such as "09/2016").
    """

    def __init__(self, path: str, name: str, version: str, ev_oids: Optional[List[str]] = None) -> None:
        self.path = path
        self.name = name
        self.version = version

        # Used for pickling
        self.__ev_oids_as_str = ev_oids
        self.ev_oids: List[ObjectIdentifier] = []
        self.__parse_ev_oids()

        self._subject_to_certificate_dict = self._compute_subject_certificate_dict(self.path)

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
        pickable_dict['_subject_to_certificate_dict'] = None
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

    @staticmethod
    def _compute_subject_certificate_dict(path: str) -> Dict[Name, Certificate]:
        cert_dict = {}
        with io.open(path, encoding='utf-8') as store_file:
            store_content = store_file.read()
            # Each certificate is separated by -----BEGIN CERTIFICATE-----
            pem_cert_list = store_content.split('-----BEGIN CERTIFICATE-----')[1::]
            pem_cert_nb = 0
            for pem_split in pem_cert_list:
                # Remove PEM comments as they may cause Unicode errors
                final_pem = '-----BEGIN CERTIFICATE-----{}-----END CERTIFICATE-----'.format(
                    pem_split.split('-----END CERTIFICATE-----')[0]
                ).strip()
                cert = load_pem_x509_certificate(final_pem.encode(encoding='ascii'), default_backend())
                # Store a dictionary of subject->certificate for easy lookup
                try:
                    cert_dict[cert.subject] = cert
                except ValueError:
                    if pem_cert_nb == 311:
                        # Cert number 311 in the Mozilla store can't be parsed by cryptography
                        continue
                    raise

                pem_cert_nb += 1

        return cert_dict

    def _get_certificate_with_subject(self, certificate_subject: Name) -> Optional[Certificate]:
        return self._subject_to_certificate_dict.get(certificate_subject, None)

    @staticmethod
    def _is_certificate_chain_order_valid(certificate_chain: List[Certificate]) -> bool:
        previous_issuer = None
        for index, cert in enumerate(certificate_chain):
            current_subject = cert.subject

            if index > 0:
                # Compare the current subject with the previous issuer in the chain
                if current_subject != previous_issuer:
                    return False
            try:
                previous_issuer = cert.issuer
            except KeyError:
                # Missing issuer; this is okay if this is the last cert
                previous_issuer = u"missing issuer {}".format(index)
        return True

    def build_verified_certificate_chain(self, received_certificate_chain: List[Certificate]) -> List[Certificate]:
        """Try to figure out the verified chain by finding the anchor/root CA the received chain chains up to in the
        trust store.

        This will not clean the certificate chain if additional/invalid certificates were sent and the signatures and
        fields (notBefore, etc.) are not verified.
        """
        # The certificates must have been sent in the correct order or we give up
        if not self._is_certificate_chain_order_valid(received_certificate_chain):
            raise InvalidCertificateChainOrderError()

        # TODO: OpenSSL 1.1.0 has SSL_get0_verified_chain() to do this directly
        verified_certificate_chain = []
        anchor_cert = None
        # Assume that the certificates were sent in the correct order or give up
        for cert in received_certificate_chain:
            anchor_cert = self._get_certificate_with_subject(cert.issuer)
            verified_certificate_chain.append(cert)
            if anchor_cert:
                verified_certificate_chain.append(anchor_cert)
                break

        if anchor_cert is None:
            # Could not build the verified chain
            raise AnchorCertificateNotInTrustStoreError()

        return verified_certificate_chain


class CouldNotBuildVerifiedChainError(ValueError):
    pass


class AnchorCertificateNotInTrustStoreError(CouldNotBuildVerifiedChainError):
    pass


class InvalidCertificateChainOrderError(CouldNotBuildVerifiedChainError):
    pass
