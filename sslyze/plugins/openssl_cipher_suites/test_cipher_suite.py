from nassl.ssl_client import OpenSslVersionEnum, ClientCertificateRequested

from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuiteScanResult, CipherSuiteScanResultEnum
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SslHandshakeRejected
from sslyze.utils.tls12_workaround import WorkaroundForTls12ForCipherSuites


def test_cipher_suite(
        server_connectivity_info: ServerConnectivityInfo,
        ssl_version: OpenSslVersionEnum,
        openssl_cipher_name: str,
        should_send_request_after_handshake: bool
) -> CipherSuiteScanResult:
    """Initiates a SSL handshake with the server using the SSL version and the cipher suite specified.
    """
    requires_legacy_openssl = True
    if ssl_version == OpenSslVersionEnum.TLSV1_2:
        # For TLS 1.2, we need to pick the right version of OpenSSL depending on which cipher suite
        requires_legacy_openssl = WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(openssl_cipher_name)
    elif ssl_version == OpenSslVersionEnum.TLSV1_3:
        requires_legacy_openssl = False

    ssl_connection = server_connectivity_info.get_preconfigured_ssl_connection(
        override_ssl_version=ssl_version, should_use_legacy_openssl=requires_legacy_openssl
    )

    # Only enable the cipher suite to test; not trivial anymore since OpenSSL 1.1.1 and TLS 1.3
    if ssl_version == OpenSslVersionEnum.TLSV1_3:
        # The function to control cipher suites is different for TLS 1.3
        # Disable the default, non-TLS 1.3 cipher suites
        ssl_connection.ssl_client.set_cipher_list("")
        # Enable the one TLS 1.3 cipher suite we want to test
        ssl_connection.ssl_client.set_ciphersuites(openssl_cipher_name)
    else:
        if not requires_legacy_openssl:
            # Disable the TLS 1.3 cipher suites if we are using the modern client
            ssl_connection.ssl_client.set_ciphersuites("")

        ssl_connection.ssl_client.set_cipher_list(openssl_cipher_name)

    if len(ssl_connection.ssl_client.get_cipher_list()) != 1:
        raise ValueError(
            f'Passed an OpenSSL string for multiple cipher suites: "{openssl_cipher_name}": '
            f"{str(ssl_connection.ssl_client.get_cipher_list())}"
        )

    post_tls_handshake_response = None
    error_message = None
    try:
        # Perform the SSL handshake
        ssl_connection.connect()

        result_enum = CipherSuiteScanResultEnum.ACCEPTED_BY_SERVER
        if should_send_request_after_handshake:
            try:
                post_tls_handshake_response = ssl_connection.send_sample_request()
            except NotImplementedError:
                # We don't have code to send a sample request for the protocol we are using with this server
                pass

    except SslHandshakeRejected as e:
        result_enum = CipherSuiteScanResultEnum.REJECTED_BY_SERVER
        error_message = str(e)

    except ClientCertificateRequested:
        # When the handshake failed due to ClientCertificateRequested
        result_enum = CipherSuiteScanResultEnum.ACCEPTED_BY_SERVER

    except Exception as e:
        result_enum = CipherSuiteScanResultEnum.UNKNOWN_ERROR
        error_message = f"{e.__class__.__name__} - {str(e)}"

    finally:
        ssl_connection.close()

    return CipherSuiteScanResult(
        result=result_enum,
        openssl_name=openssl_cipher_name,
        ssl_version=ssl_version,
        post_tls_handshake_response=post_tls_handshake_response,
        error_message=error_message,
    )
