import ssl
from dataclasses import dataclass
from ssl import CertificateError
from typing import Optional, List

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ExtensionNotFound, ExtensionOID, Certificate
from nassl.ocsp_response import OcspResponseStatusEnum, OcspResponseNotTrustedError, OcspResponse

from sslyze.plugins.certificate_info.symantec import SymantecDistructTester
from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore
from sslyze.plugins.certificate_info.trust_stores.trust_store_repository import TrustStoresRepository
from sslyze.plugins.utils.certificate_utils import CertificateUtils


@dataclass(frozen=True)
class CertificateChainDeploymentAnalysisResult:

    leaf_certificate_subject_matches_hostname: bool
    leaf_certificate_has_must_staple_extension: bool
    leaf_certificate_is_ev: bool
    leaf_certificate_signed_certificate_timestamps_count: Optional[int]
    received_chain_contains_anchor_certificate: Optional[bool]
    received_chain_has_valid_order: bool
    verified_chain_has_sha1_signature: Optional[bool]
    verified_chain_has_legacy_symantec_anchor: Optional[bool]
    ocsp_response_is_trusted: Optional[bool]
    ocsp_response_status: Optional[OcspResponseStatusEnum]


class CertificateChainDeploymentAnalyzer:
    """Utility class for analyzing a certificate chain as deployed on a specific server.

    Useful for checking a server's certificate chain without having to use the CertificateInfoPlugin.
    """

    def __init__(
        self,
        server_hostname: str,
        received_chain: List[Certificate],
        verified_chain: Optional[List[Certificate]],
        trust_store_used_to_build_verified_chain: Optional[TrustStore],
        received_ocsp_response: Optional[OcspResponse],
    ) -> None:
        self.server_hostname = server_hostname
        self.received_certificate_chain = received_chain
        self.verified_certificate_chain = verified_chain
        self.trust_store_used_to_build_verified_chain = trust_store_used_to_build_verified_chain
        self.received_ocsp_response = received_ocsp_response

    def perform(self) -> CertificateChainDeploymentAnalysisResult:
        """Run the analysis.
        """
        leaf_cert = self.received_certificate_chain[0]

        # OCSP Must-Staple
        has_ocsp_must_staple = False
        try:
            tls_feature_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
            for feature_type in tls_feature_ext.value:
                if feature_type == cryptography.x509.TLSFeatureType.status_request:
                    has_ocsp_must_staple = True
                    break
        except ExtensionNotFound:
            pass

        # Received chain order
        is_chain_order_valid = True
        previous_issuer = None
        for index, cert in enumerate(self.received_certificate_chain):
            current_subject = cert.subject

            if index > 0:
                # Compare the current subject with the previous issuer in the chain
                if current_subject != previous_issuer:
                    is_chain_order_valid = False
                    break
            try:
                previous_issuer = cert.issuer
            except KeyError:
                # Missing issuer; this is okay if this is the last cert
                previous_issuer = "missing issuer {}".format(index)

        # Check if it is EV - we only have the EV OIDs for Mozilla
        is_leaf_certificate_ev = (
            TrustStoresRepository.get_default()
            .get_main_store()
            .is_certificate_extended_validation(self.received_certificate_chain[0])
        )

        # Check for Signed Timestamps
        number_of_scts: Optional[int] = 0
        try:
            # Look for the x509 extension
            sct_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)

            if isinstance(sct_ext.value, cryptography.x509.UnrecognizedExtension):
                # The version of OpenSSL on the system is too old and can't parse the SCT extension
                number_of_scts = None

            # Count the number of entries in the extension
            number_of_scts = len(sct_ext.value)
        except ExtensionNotFound:
            pass

        # Check if the anchor was sent by the server
        has_anchor_in_certificate_chain = None
        if self.verified_certificate_chain:
            has_anchor_in_certificate_chain = self.verified_certificate_chain[-1] in self.received_certificate_chain

        # Check hostname validation
        try:
            CertificateUtils.certificate_matches_hostname(leaf_cert, self.server_hostname)
            certificate_matches_hostname = True
        except CertificateError:
            certificate_matches_hostname = False

        # Check if a SHA1-signed certificate is in the chain
        # Root certificates can still be signed with SHA1 so we only check leaf and intermediate certificates
        has_sha1_in_certificate_chain = None
        if self.verified_certificate_chain:
            has_sha1_in_certificate_chain = False
            for cert in self.verified_certificate_chain[:-1]:
                if isinstance(cert.signature_hash_algorithm, hashes.SHA1):
                    has_sha1_in_certificate_chain = True
                    break

        # Check if this is a distrusted Symantec-issued chain
        verified_chain_has_legacy_symantec_anchor = None
        if self.verified_certificate_chain:
            symantec_distrust_timeline = SymantecDistructTester.get_distrust_timeline(self.verified_certificate_chain)
            verified_chain_has_legacy_symantec_anchor = True if symantec_distrust_timeline else False

        # Check the OCSP response if there is one
        is_ocsp_response_trusted = None
        ocsp_response_status = None
        if self.received_ocsp_response:
            ocsp_response_status = self.received_ocsp_response.status
            if (
                self.trust_store_used_to_build_verified_chain
                and ocsp_response_status == OcspResponseStatusEnum.SUCCESSFUL
            ):
                try:
                    self.received_ocsp_response.verify(self.trust_store_used_to_build_verified_chain.path)
                    is_ocsp_response_trusted = True
                except OcspResponseNotTrustedError:
                    is_ocsp_response_trusted = False

        return CertificateChainDeploymentAnalysisResult(
            leaf_certificate_subject_matches_hostname=certificate_matches_hostname,
            leaf_certificate_has_must_staple_extension=has_ocsp_must_staple,
            leaf_certificate_is_ev=is_leaf_certificate_ev,
            leaf_certificate_signed_certificate_timestamps_count=number_of_scts,
            received_chain_contains_anchor_certificate=has_anchor_in_certificate_chain,
            received_chain_has_valid_order=is_chain_order_valid,
            verified_chain_has_sha1_signature=has_sha1_in_certificate_chain,
            verified_chain_has_legacy_symantec_anchor=verified_chain_has_legacy_symantec_anchor,
            ocsp_response_is_trusted=is_ocsp_response_trusted,
            ocsp_response_status=ocsp_response_status,
        )
