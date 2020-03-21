from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuitesRepository
from sslyze.server_connectivity import TlsVersionEnum


class TestCipherSuiteMappings:
    def test_names_mapping_legacy_ssl_client(self):
        for tls_version, expected_cipher_suites_count in [
            (TlsVersionEnum.SSL_2_0, 7),
            (TlsVersionEnum.SSL_3_0, 121),
            (TlsVersionEnum.TLS_1_0, 121),
            (TlsVersionEnum.TLS_1_1, 121),
            (TlsVersionEnum.TLS_1_2, 160),
            (TlsVersionEnum.TLS_1_3, 5),
        ]:
            all_cipher_suites = CipherSuitesRepository.get_all_cipher_suites(tls_version)
            assert expected_cipher_suites_count == len(all_cipher_suites)
            for cipher_suite in all_cipher_suites:
                assert cipher_suite.name
                assert cipher_suite.key_size is not None
                assert cipher_suite.is_anonymous is not None
