from nassl.ssl_client import OpenSslVerifyEnum
from nassl.ssl_client import OpenSslVersionEnum
from nassl.legacy_ssl_client import LegacySslClient


class WorkaroundForTls12ForCipherSuites:
    """Helper to figure out which version of OpenSSL to use for a given TLS 1.2 cipher suite.

    The nassl module supports using either a legacy or a modern version of OpenSSL. When using TLS 1.2, specific cipher
    suites are only supported by one of the two implementation.
    """

    @classmethod
    def requires_legacy_openssl(cls, openssl_cipher_name: str) -> bool:
        # Get the list of all ciphers supported by the legacy OpenSSL
        legacy_client = LegacySslClient(ssl_version=OpenSslVersionEnum.TLSV1_2, ssl_verify=OpenSslVerifyEnum.NONE)
        legacy_client.set_cipher_list("ALL:COMPLEMENTOFALL")
        legacy_ciphers = legacy_client.get_cipher_list()

        # Always use the legacy client if it supports the cipher suite, as the modern OpenSSL (1.1.x) does not support
        # weak ciphers, even with the right compilation options; the handshake fails with a "no ciphers available" error
        # but it actually means that OpenSSL does not support the cipher
        return openssl_cipher_name in legacy_ciphers
