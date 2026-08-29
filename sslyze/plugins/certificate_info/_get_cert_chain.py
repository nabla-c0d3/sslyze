from pathlib import Path

from nassl.base_ssl_client import ClientCertificateRequested
from nassl.openssl_1_1_1._nassl import OCSP_RESPONSE

from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum

ArgumentsToGetCertificateChain = tuple[ServerConnectivityInfo, Path | None, TlsVersionEnum | None, str | None, bool]


def get_certificate_chain(
    server_info: ServerConnectivityInfo,
    custom_ca_file: Path | None,
    tls_version: TlsVersionEnum | None,
    openssl_cipher_string: str | None,
    should_enable_sni: bool,
) -> tuple[list[str], OCSP_RESPONSE | None, Path | None, bool]:
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, should_enable_server_name_indication=should_enable_sni
    )
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

    return received_chain_as_pem, ocsp_response, custom_ca_file, should_enable_sni
