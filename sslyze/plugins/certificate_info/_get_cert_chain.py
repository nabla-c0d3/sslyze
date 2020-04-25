from pathlib import Path
from typing import List, Optional, Tuple

import nassl
from nassl.ssl_client import ClientCertificateRequested, OpenSslVersionEnum

from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum

ArgumentsToGetCertificateChain = Tuple[ServerConnectivityInfo, Optional[Path], Optional[TlsVersionEnum], Optional[str]]


def get_certificate_chain(
    server_info: ServerConnectivityInfo,
    custom_ca_file: Optional[Path],
    tls_version: Optional[TlsVersionEnum],
    openssl_cipher_string: Optional[str],
) -> Tuple[List[str], Optional[nassl.ocsp_response.OcspResponse], Optional[Path]]:
    ssl_connection = server_info.get_preconfigured_tls_connection(override_tls_version=tls_version)
    if openssl_cipher_string:
        ssl_connection.ssl_client.set_cipher_list(openssl_cipher_string)

    # Enable OCSP stapling
    ssl_connection.ssl_client.set_tlsext_status_ocsp()

    # Enable Server Name Indication in order to get the right certificate
    # We only enable SNI for the certificate_info check because SNI can make other checks miss issues
    # See https://github.com/nabla-c0d3/sslyze/issues/202
    if ssl_connection.ssl_client._ssl_version != OpenSslVersionEnum.SSLV2:
        # SNI is not available with SSL 2.0
        # TODO(AD): Modify set_tlsext_host_name() to return an exception so we dont need to look at _ssl_version
        ssl_connection.ssl_client.set_tlsext_host_name(server_info.network_configuration.tls_server_name_indication)

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
