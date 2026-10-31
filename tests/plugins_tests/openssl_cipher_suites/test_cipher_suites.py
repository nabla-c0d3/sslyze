import pytest

from sslyze.plugins.openssl_cipher_suites.cipher_suites import retrieve_all_available_cipher_suites
from sslyze.server_connectivity import TlsVersionEnum


class TestAvailableCipherSuites:
    @pytest.mark.parametrize(
        "tls_version, expected_cipher_suites_count",
        [
            (TlsVersionEnum.SSL_2_0, 7),
            (TlsVersionEnum.SSL_3_0, 121),
            (TlsVersionEnum.TLS_1_0, 161),
            (TlsVersionEnum.TLS_1_1, 161),
            (TlsVersionEnum.TLS_1_2, 161),
            (TlsVersionEnum.TLS_1_3, 5),
        ],
    )
    def test_all_available_cipher_suites(self, tls_version, expected_cipher_suites_count):
        all_cipher_suites = retrieve_all_available_cipher_suites(tls_version)
        assert expected_cipher_suites_count == len(all_cipher_suites)
        for cipher_suite in all_cipher_suites:
            assert cipher_suite.name
            assert cipher_suite.key_size is not None
            assert cipher_suite.is_anonymous is not None
