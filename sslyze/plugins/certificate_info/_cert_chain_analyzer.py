from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from ssl import CertificateError, match_hostname
from typing import Optional, List, cast

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ExtensionNotFound, ExtensionOID, Certificate, load_pem_x509_certificate
from nassl._nassl import X509
from nassl.cert_chain_verifier import CertificateChainVerifier, CertificateChainVerificationFailed
import nassl.ocsp_response

from sslyze.plugins.certificate_info._certificate_utils import extract_dns_subject_alternative_names, get_common_names
from sslyze.plugins.certificate_info._symantec import SymantecDistructTester
from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore


@dataclass(frozen=True)
class PathValidationResult:
    """The result of trying to validate a server's certificate chain using a specific trust store.

    Attributes:
        trust_stores: The trust store used for validation.
        verified_certificate_chain: The verified certificate chain returned by OpenSSL.
            Index 0 is the leaf certificate and the last element is the anchor/CA certificate from the trust store.
            Will be None if the validation failed or the verified chain could not be built.
            Each certificate is parsed using the cryptography module; documentation is available at
            https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object.
        openssl_error_string: The result string returned by OpenSSL's validation function; None if validation was
            successful.
        was_validation_successful: Whether the certificate chain is trusted when using supplied the trust_stores.
    """

    trust_store: TrustStore
    verified_certificate_chain: Optional[List[Certificate]]
    openssl_error_string: Optional[str]

    @property
    def was_validation_successful(self) -> bool:
        return True if self.verified_certificate_chain else False


class OcspResponseStatusEnum(Enum):
    # WARNING: The order must match nassl.ocsp_response.OcspResponseStatusEnum
    SUCCESSFUL = 0
    MALFORMED_REQUEST = 1
    INTERNAL_ERROR = 2
    TRY_LATER = 3
    SIG_REQUIRED = 5
    UNAUTHORIZED = 6


@dataclass(frozen=True)
class OcspResponse:
    status: OcspResponseStatusEnum
    type: str
    version: int
    responder_id: str
    produced_at: datetime

    certificate_status: str
    this_update: datetime
    next_update: datetime

    hash_algorithm: str
    issuer_name_hash: str
    issuer_key_hash: str
    serial_number: str

    # Only SCT is supported at the moment
    extensions: Optional[List[nassl.ocsp_response.SignedCertificateTimestampsExtension]]


@dataclass(frozen=True)
class CertificateDeploymentAnalysisResult:
    """The result of analyzing a server's certificate to verify its validity.

    Any certificate available as an attribute is parsed using the cryptography module; documentation is available at
    https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object

    Attributes:
        received_certificate_chain: The certificate chain sent by the server; index 0 is the leaf certificate.
        verified_certificate_chain: The verified certificate chain returned by OpenSSL for one of the trust stores
            packaged within SSLyze. Will be ``None`` if the validation failed with all of the available trust stores
            (Apple, Mozilla, etc.). This is essentially a shortcut to
            ``path_validation_result_list[0].verified_certificate_chain``.
        path_validation_results: The result of validating the server's
            certificate chain using each trust store that is packaged with SSLyze (Mozilla, Apple, etc.).
            If for a given trust store, the validation was successful, the verified certificate chain built by OpenSSL
            can be retrieved from the ``PathValidationResult``.
        leaf_certificate_subject_matches_hostname: ``True`` if the leaf certificate's Common Name or Subject Alternative
            Names match the server's hostname.
        leaf_certificate_is_ev: ``True`` if the leaf certificate is Extended Validation, according to Mozilla.
        leaf_certificate_has_must_staple_extension: ``True`` if the OCSP must-staple extension is present in the leaf
            certificate.
        leaf_certificate_signed_certificate_timestamps_count: The number of Signed Certificate
            Timestamps (SCTs) for Certificate Transparency embedded in the leaf certificate. ``None`` if the version of
            OpenSSL installed on the system is too old to be able to parse the SCT extension.
        received_chain_has_valid_order: ``True`` if the certificate chain returned by the server was sent in the right
            order.
        received_chain_contains_anchor_certificate: ``True`` if the server included the anchor/root
            certificate in the chain it sends back to clients. ``None`` if the verified chain could not be built.
        verified_chain_has_sha1_signature: ``True`` if any of the leaf or intermediate certificates are
            signed using the SHA-1 algorithm. ``None`` if the verified chain could not be built.
        verified_chain_has_legacy_symantec_anchor: ``True`` if the certificate chain contains a distrusted Symantec
            anchor
            (https://blog.qualys.com/ssllabs/2017/09/26/google-and-mozilla-deprecating-existing-symantec-certificates).
            ``None`` if the verified chain could not be built.
        ocsp_response: The OCSP response returned by the server. ``None`` if no response was sent by the server or if
            the scan was run through an HTTP proxy (the proxy will not forward the server's OCSP response).
        ocsp_response_is_trusted: ``True`` if the OCSP response is trusted using the Mozilla trust store.
            ``None`` if no OCSP response was sent by the server.

    """

    received_certificate_chain: List[Certificate]
    leaf_certificate_subject_matches_hostname: bool
    leaf_certificate_has_must_staple_extension: bool
    leaf_certificate_is_ev: bool
    leaf_certificate_signed_certificate_timestamps_count: Optional[int]
    received_chain_contains_anchor_certificate: Optional[bool]
    received_chain_has_valid_order: bool

    path_validation_results: List[PathValidationResult]
    verified_chain_has_sha1_signature: Optional[bool]
    verified_chain_has_legacy_symantec_anchor: Optional[bool]

    ocsp_response: Optional[OcspResponse]
    ocsp_response_is_trusted: Optional[bool]

    @property
    def verified_certificate_chain(self) -> Optional[List[Certificate]]:
        """Get one of the verified certificate chains if one was successfully built using any of the trust stores.
        """
        for path_result in self.path_validation_results:
            if path_result.was_validation_successful:
                return path_result.verified_certificate_chain
        return None

    @property
    def verified_certificate_chain_as_pem(self) -> Optional[List[str]]:
        if self.verified_certificate_chain is None:
            return None

        pem_certs = []
        for certificate in self.verified_certificate_chain:
            pem_certs.append(certificate.public_bytes(Encoding.PEM).decode("ascii"))
        return pem_certs

    @property
    def received_certificate_chain_as_pem(self) -> List[str]:
        pem_certs = []
        for certificate in self.received_certificate_chain:
            pem_certs.append(certificate.public_bytes(Encoding.PEM).decode("ascii"))
        return pem_certs


class CertificateDeploymentAnalyzer:
    """Utility class for analyzing a certificate chain as deployed on a specific server.

    Useful for checking a server's certificate chain without having to use the CertificateInfoPlugin.
    """

    def __init__(
        self,
        server_hostname: str,
        server_certificate_chain_as_pem: List[str],
        server_ocsp_response: Optional[nassl.ocsp_response.OcspResponse],
        trust_stores_for_validation: List[TrustStore],
    ) -> None:
        self.server_hostname = server_hostname
        self.server_certificate_chain_as_pem = server_certificate_chain_as_pem
        self.server_ocsp_response = server_ocsp_response
        self.trust_stores_for_validation = trust_stores_for_validation

    def perform(self) -> CertificateDeploymentAnalysisResult:
        received_certificate_chain = [
            load_pem_x509_certificate(pem_cert.encode("ascii"), backend=default_backend())
            for pem_cert in self.server_certificate_chain_as_pem
        ]
        leaf_cert = received_certificate_chain[0]

        # OCSP Must-Staple
        has_ocsp_must_staple = False
        try:
            tls_feature_ext = cast(
                cryptography.x509.TLSFeature, leaf_cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
            )
            for feature_type in tls_feature_ext.value:
                if feature_type == cryptography.x509.TLSFeatureType.status_request:
                    has_ocsp_must_staple = True
                    break
        except ExtensionNotFound:
            pass

        # Received chain order
        is_chain_order_valid = True
        previous_issuer = None
        for index, cert in enumerate(received_certificate_chain):
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
                previous_issuer = None

        # Check if the leaf certificate is Extended Validation
        is_leaf_certificate_ev = False
        for trust_store in self.trust_stores_for_validation:
            if trust_store.ev_oids is None:
                # We only have the EV OIDs for Mozilla - skip other stores
                continue

            is_leaf_certificate_ev = trust_store.is_certificate_extended_validation(leaf_cert)

        # Check for Signed Timestamps
        number_of_scts: Optional[int] = 0
        try:
            # Look for the x509 extension
            sct_ext = leaf_cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
            if isinstance(sct_ext.value, cryptography.x509.UnrecognizedExtension):
                # The version of OpenSSL on the system is too old and can't parse the SCT extension
                number_of_scts = None

            # Count the number of entries in the extension
            sct_ext_value = cast(cryptography.x509.PrecertificateSignedCertificateTimestamps, sct_ext.value)
            number_of_scts = len(sct_ext_value)
        except ExtensionNotFound:
            pass

        # Try to generate the verified certificate chain using each trust store
        all_path_validation_results = []
        for trust_store in self.trust_stores_for_validation:
            path_validation_result = _verify_certificate_chain(self.server_certificate_chain_as_pem, trust_store)
            all_path_validation_results.append(path_validation_result)

        # Keep one trust store that was able to build the verified chain to then run additional checks
        trust_store_that_can_build_verified_chain = None
        verified_certificate_chain = None

        # But first tort the path validation results so the same trust_store always get picked for a given server
        def sort_function(path_validation: PathValidationResult) -> str:
            return path_validation.trust_store.name.lower()

        all_path_validation_results.sort(key=sort_function)

        # Then keep a trust store with a verified chain
        for path_validation_result in all_path_validation_results:
            if path_validation_result.was_validation_successful:
                trust_store_that_can_build_verified_chain = path_validation_result.trust_store
                verified_certificate_chain = path_validation_result.verified_certificate_chain
                break

        # Check if the anchor was sent by the server
        has_anchor_in_certificate_chain = None
        if verified_certificate_chain:
            has_anchor_in_certificate_chain = verified_certificate_chain[-1] in received_certificate_chain

        # Check if a SHA1-signed certificate is in the chain
        # Root certificates can still be signed with SHA1 so we only check leaf and intermediate certificates
        has_sha1_in_certificate_chain = None
        if verified_certificate_chain:
            has_sha1_in_certificate_chain = False
            for cert in verified_certificate_chain[:-1]:
                if isinstance(cert.signature_hash_algorithm, hashes.SHA1):
                    has_sha1_in_certificate_chain = True
                    break

        # Check if this is a distrusted Symantec-issued chain
        verified_chain_has_legacy_symantec_anchor = None
        if verified_certificate_chain:
            symantec_distrust_timeline = SymantecDistructTester.get_distrust_timeline(verified_certificate_chain)
            verified_chain_has_legacy_symantec_anchor = True if symantec_distrust_timeline else False

        # Check the OCSP response if there is one
        is_ocsp_response_trusted = None
        final_ocsp_response = None
        if self.server_ocsp_response:
            # Convert the OCSP response from the nassl class to the sslyze class to ensure API stability
            final_ocsp_response = OcspResponse(
                status=OcspResponseStatusEnum(self.server_ocsp_response.status.value),
                type=self.server_ocsp_response.type,
                version=self.server_ocsp_response.version,
                responder_id=self.server_ocsp_response.responder_id,
                produced_at=self.server_ocsp_response.produced_at,
                certificate_status=self.server_ocsp_response.certificate_status,
                this_update=self.server_ocsp_response.this_update,
                next_update=self.server_ocsp_response.next_update,
                hash_algorithm=self.server_ocsp_response.hash_algorithm,
                issuer_name_hash=self.server_ocsp_response.issuer_name_hash,
                issuer_key_hash=self.server_ocsp_response.issuer_key_hash,
                serial_number=self.server_ocsp_response.serial_number,
                extensions=self.server_ocsp_response.extensions,
            )

            # Check if the OCSP response is trusted
            if (
                trust_store_that_can_build_verified_chain
                and self.server_ocsp_response.status == nassl.ocsp_response.OcspResponseStatusEnum.SUCCESSFUL
            ):
                try:
                    self.server_ocsp_response.verify(trust_store_that_can_build_verified_chain.path)
                    is_ocsp_response_trusted = True
                except nassl.ocsp_response.OcspResponseNotTrustedError:
                    is_ocsp_response_trusted = False

        # All done
        return CertificateDeploymentAnalysisResult(
            received_certificate_chain=received_certificate_chain,
            leaf_certificate_subject_matches_hostname=_certificate_matches_hostname(leaf_cert, self.server_hostname),
            leaf_certificate_has_must_staple_extension=has_ocsp_must_staple,
            leaf_certificate_is_ev=is_leaf_certificate_ev,
            leaf_certificate_signed_certificate_timestamps_count=number_of_scts,
            received_chain_contains_anchor_certificate=has_anchor_in_certificate_chain,
            received_chain_has_valid_order=is_chain_order_valid,
            verified_chain_has_sha1_signature=has_sha1_in_certificate_chain,
            verified_chain_has_legacy_symantec_anchor=verified_chain_has_legacy_symantec_anchor,
            path_validation_results=all_path_validation_results,
            ocsp_response=final_ocsp_response,
            ocsp_response_is_trusted=is_ocsp_response_trusted,
        )


def _certificate_matches_hostname(certificate: Certificate, server_hostname: str) -> bool:
    """Verify that the certificate was issued for the given hostname.
    """
    # Extract the names from the certificate to create the properly-formatted dictionary
    certificate_names = {
        "subject": (tuple([("commonName", name) for name in get_common_names(certificate.subject)]),),
        "subjectAltName": tuple([("DNS", name) for name in extract_dns_subject_alternative_names(certificate)]),
    }
    # CertificateError is raised on failure
    try:
        match_hostname(certificate_names, server_hostname)  # type: ignore
        return True
    except CertificateError:
        return False


def _verify_certificate_chain(server_certificate_chain: List[str], trust_store: TrustStore) -> PathValidationResult:
    server_chain_as_x509s = [X509(pem_cert) for pem_cert in server_certificate_chain]
    chain_verifier = CertificateChainVerifier.from_file(trust_store.path)

    verified_chain: Optional[List[Certificate]]
    try:
        openssl_verify_str = None
        verified_chain_as_509s = chain_verifier.verify(server_chain_as_x509s)
        verified_chain = [
            load_pem_x509_certificate(x509_cert.as_pem().encode("ascii"), backend=default_backend())
            for x509_cert in verified_chain_as_509s
        ]
    except CertificateChainVerificationFailed as e:
        verified_chain = None
        openssl_verify_str = e.openssl_error_string

    return PathValidationResult(
        trust_store=trust_store, verified_certificate_chain=verified_chain, openssl_error_string=openssl_verify_str
    )
