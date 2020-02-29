from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import OpenSslVersionEnum, SslClient

from sslyze.plugins.openssl_cipher_suites.cipher_suites import (
    _SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING,
    _RFC_NAME_TO_KEY_SIZE_MAPPING,
    _TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
)


class TestCipherSuiteMappings:
    def test_names_mapping_sslv2(self):
        ssl_client = LegacySslClient(ssl_version=OpenSslVersionEnum.SSLV2)
        ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
        for openssl_cipher_name in ssl_client.get_cipher_list():
            assert openssl_cipher_name in _SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING
            rfc_name = _SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING[openssl_cipher_name]
            assert rfc_name in _RFC_NAME_TO_KEY_SIZE_MAPPING

    def test_names_mapping_legacy_ssl_client(self):
        for ssl_version in [
            OpenSslVersionEnum.SSLV3,
            OpenSslVersionEnum.TLSV1,
            OpenSslVersionEnum.TLSV1_1,
            OpenSslVersionEnum.TLSV1_2,
        ]:
            ssl_client = LegacySslClient(ssl_version=ssl_version)
            ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
            for openssl_cipher_name in ssl_client.get_cipher_list():
                assert openssl_cipher_name in _TLS_OPENSSL_TO_RFC_NAMES_MAPPING
                rfc_name = _TLS_OPENSSL_TO_RFC_NAMES_MAPPING[openssl_cipher_name]
                assert rfc_name in _RFC_NAME_TO_KEY_SIZE_MAPPING

    def test_names_mapping_modern_ssl_client(self):
        for tls_version in [OpenSslVersionEnum.TLSV1_2, OpenSslVersionEnum.TLSV1_3]:
            ssl_client = SslClient(ssl_version=tls_version)
            ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
            for openssl_cipher_name in ssl_client.get_cipher_list():
                assert openssl_cipher_name in _TLS_OPENSSL_TO_RFC_NAMES_MAPPING
                rfc_name = _TLS_OPENSSL_TO_RFC_NAMES_MAPPING[openssl_cipher_name]
                assert rfc_name in _RFC_NAME_TO_KEY_SIZE_MAPPING
