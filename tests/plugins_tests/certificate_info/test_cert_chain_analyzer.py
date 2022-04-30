from sslyze.plugins.certificate_info.trust_stores.trust_store_repository import TrustStoresRepository
from sslyze.plugins.certificate_info._cert_chain_analyzer import (
    _cache_for_trusted_certificates_per_file,
    _convert_and_cache_pem_certs_to_x509s,
)


class TestMemoryLeakWorkaroundWithX509Cache:
    def test(self):
        # Given a path to a file with a list of PEM certificates
        trusted_certificates_path = TrustStoresRepository.get_default().get_main_store().path

        # And the file's content has not been cached yet
        assert trusted_certificates_path not in _cache_for_trusted_certificates_per_file

        # When converting the content of the file to X509 objects
        certs_as_x509s = _convert_and_cache_pem_certs_to_x509s(trusted_certificates_path)

        # It succeeds, and the x509 objects were cached
        assert certs_as_x509s
        assert trusted_certificates_path in _cache_for_trusted_certificates_per_file
