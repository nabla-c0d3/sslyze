from pathlib import Path
from typing import List, Optional, Tuple

import nassl
from nassl.ssl_client import ClientCertificateRequested

from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum

ArgumentsToGetCertificateChain = Tuple[ServerConnectivityInfo, Optional[Path], Optional[TlsVersionEnum], Optional[str]]


def get_certificate_chain(
    server_info: ServerConnectivityInfo,
    custom_ca_file: Optional[Path],
    tls_version: Optional[TlsVersionEnum],
    openssl_cipher_string: Optional[str],
) -> Tuple[List[str], Optional[nassl._nassl.OCSP_RESPONSE], Optional[Path]]:
    ssl_connection = server_info.get_preconfigured_tls_connection(override_tls_version=tls_version)
    if openssl_cipher_string:
        ssl_connection.ssl_client.set_cipher_list(openssl_cipher_string)

    # Enable OCSP stapling
    ssl_connection.ssl_client.set_tlsext_status_ocsp()

    try:
        ssl_connection.connect()
        ocsp_response = ssl_connection.ssl_client.get_tlsext_status_ocsp_resp()
        received_chain_as_pem = ssl_connection.ssl_client.get_received_chain()

    except ClientCertificateRequested:
        ocsp_response = ssl_connection.ssl_client.get_tlsext_status_ocsp_resp()
        received_chain_as_pem = ssl_connection.ssl_client.get_received_chain()

    finally:
        ssl_connection.close()

    return received_chain_as_pem, ocsp_response, custom_ca_file
