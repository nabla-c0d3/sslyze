from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, Certificate
from nassl._nassl import X509
from nassl.cert_chain_verifier import CertificateChainVerifier
from nassl.ocsp_response import SignedCertificateTimestampsExtension, OcspResponseStatusEnum, OcspResponse
from nassl.ssl_client import CertificateChainVerificationFailed, ClientCertificateRequested

from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore
from sslyze.plugins.certificate_info.trust_stores.trust_store_repository import TrustStoresRepository
from sslyze.server_connectivity import ServerConnectivityInfo


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
        openssL_error_string: The result string returned by OpenSSL's validation function; None if validation was
            successful.
        was_validation_successful: Whether the certificate chain is trusted when using supplied the trust_stores.
    """

    trust_store: TrustStore
    verified_certificate_chain: Optional[List[Certificate]]
    openssL_error_string: Optional[str]

    @property
    def was_validation_successful(self) -> bool:
        return True if self.verified_certificate_chain else False


def get_and_verify_certificate_chain(
    server_info: ServerConnectivityInfo, custom_ca_file: Optional[Path]
) -> Tuple[List[Certificate], List[PathValidationResult], Optional[OcspResponse]]:
    # First retrieve the certificate chain from the server
    received_chain_as_pem, ocsp_response = _get_certificate_chain(server_info)

    # Then validate the chain with each trust store
    final_trust_store_list = TrustStoresRepository.get_default().get_all_stores()
    if custom_ca_file:
        final_trust_store_list.append(TrustStore(custom_ca_file, "Supplied CA file", "N/A"))

    all_validation_results = []
    for trust_store in final_trust_store_list:
        path_validation_result = _verify_certificate_chain(received_chain_as_pem, trust_store)
        all_validation_results.append(path_validation_result)

    received_chain = [
        load_pem_x509_certificate(pem_cert.encode("ascii"), backend=default_backend())
        for pem_cert in received_chain_as_pem
    ]
    return received_chain, all_validation_results, ocsp_response


def _get_certificate_chain(server_info: ServerConnectivityInfo) -> Tuple[List[str], Optional[OcspResponse]]:
    ssl_connection = server_info.get_preconfigured_tls_connection()

    # Enable OCSP stapling
    ssl_connection.ssl_client.set_tlsext_status_ocsp()

    try:
        ssl_connection.connect()
        ocsp_response = ssl_connection.ssl_client.get_tlsext_status_ocsp_resp()
        received_chain_as_pem = ssl_connection.ssl_client.get_received_chain()

    finally:
        ssl_connection.close()

    return received_chain_as_pem, ocsp_response


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
        trust_store=trust_store,
        verified_certificate_chain=verified_chain,
        openssL_error_string=openssl_verify_str,
    )
