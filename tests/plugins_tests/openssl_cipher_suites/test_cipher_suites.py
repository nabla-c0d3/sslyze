from nassl.ssl_client import OpenSslVersionEnum

from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuitesRepository


class TestCipherSuiteMappings:
    def test_names_mapping_legacy_ssl_client(self):
        for tls_version, expected_cipher_suites_count in [
            (OpenSslVersionEnum.SSLV2, 7),
            (OpenSslVersionEnum.SSLV3, 121),
            (OpenSslVersionEnum.TLSV1, 121),
            (OpenSslVersionEnum.TLSV1_1, 121),
            (OpenSslVersionEnum.TLSV1_2, 160),
            (OpenSslVersionEnum.TLSV1_3, 5),
        ]:
            all_cipher_suites = CipherSuitesRepository.get_all_cipher_suites(tls_version)
            assert expected_cipher_suites_count == len(all_cipher_suites)
            for cipher_suite in all_cipher_suites:
                assert cipher_suite.name
                assert cipher_suite.key_size is not None
                assert cipher_suite.is_anonymous is not None
