from dataclasses import dataclass
from typing import List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate, Certificate
from nassl.ssl_client import CouldNotBuildVerifiedChain, ClientCertificateRequested

from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore
from sslyze.server_connectivity_tester import ServerConnectivityInfo


@dataclass(frozen=True)
class OcspResponse:
    pass  # TODo


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
        openssL_verify_string: The result string returned by OpenSSL's validation function.
        was_validation_successful: Whether the certificate chain is trusted when using supplied the trust_stores.
    """

    trust_store: TrustStore
    verified_certificate_chain: Optional[List[Certificate]]
    openssL_verify_string: str

    @property
    def was_validation_successful(self) -> bool:
        return True if self.verified_certificate_chain else False


def get_and_verify_certificate_chain(
    server_info: ServerConnectivityInfo, trust_store: TrustStore
) -> Tuple[List[str], PathValidationResult, Optional[OcspResponse]]:
    """Connect to the target server and uses the supplied trust store to validate the server's certificate.
    """
    ssl_connection = server_info.get_preconfigured_ssl_connection(ca_certificates_path=trust_store.path)

    # Enable OCSP stapling
    ssl_connection.ssl_client.set_tlsext_status_ocsp()

    try:  # Perform the SSL handshake
        ssl_connection.connect()

        ocsp_response = ssl_connection.ssl_client.get_tlsext_status_ocsp_resp()
        received_chain_as_pem = ssl_connection.ssl_client.get_received_chain()
        try:
            verified_chain_as_pem = ssl_connection.ssl_client.get_verified_chain()
        except CouldNotBuildVerifiedChain:
            verified_chain_as_pem = None
        except AttributeError:
            # Only the modern SSL Client can build the verified chain; hence we get here if the server only supports
            # an older version of TLS (pre 1.2)
            verified_chain_as_pem = None

        (_, verify_str) = ssl_connection.ssl_client.get_certificate_chain_verify_result()

    except ClientCertificateRequested:  # The server asked for a client cert
        # We can get the server cert anyway
        ocsp_response = ssl_connection.ssl_client.get_tlsext_status_ocsp_resp()
        received_chain_as_pem = ssl_connection.ssl_client.get_received_chain()
        try:
            verified_chain_as_pem = ssl_connection.ssl_client.get_verified_chain()
        except CouldNotBuildVerifiedChain:
            verified_chain_as_pem = None
        except AttributeError:
            # Only the modern SSL Client can build the verified chain; hence we get here if the server only supports
            # an older version of TLS (pre 1.2)
            verified_chain_as_pem = None

        (_, verify_str) = ssl_connection.ssl_client.get_certificate_chain_verify_result()

    finally:
        ssl_connection.close()

    # Parse the certificates using the cryptography module
    received_chain = [
        load_pem_x509_certificate(pem_cert.encode("ascii"), backend=default_backend())
        for pem_cert in received_chain_as_pem
    ]
    verified_chain = (
        [
            load_pem_x509_certificate(cert_as_pem.encode("ascii"), backend=default_backend())
            for cert_as_pem in verified_chain_as_pem
        ]
        if verified_chain_as_pem
        else None
    )

    # TODO: Parse OCSP response

    return received_chain, PathValidationResult(trust_store, verified_chain, verify_str), ocsp_response
