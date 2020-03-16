from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

from sslyze.plugins.certificate_info._cert_chain_analyzer import _certificate_matches_hostname
from sslyze.plugins.certificate_info._certificate_utils import (
    get_common_names,
    extract_dns_subject_alternative_names,
    get_public_key_sha256,
)
from sslyze.plugins.certificate_info._cli_connector import _get_name_as_short_text

leaf_path = Path(__file__).absolute().parent / ".." / ".." / "certificates" / "github.com.pem"
leaf_pem = leaf_path.read_bytes()
certificate = load_pem_x509_certificate(leaf_pem, default_backend())


class TestCertificateUtils:
    def test_certificate_matches_hostname_good_hostname(self):
        assert _certificate_matches_hostname(certificate, "www.github.com")

    def test_certificate_matches_hostname_bad_hostname(self):
        assert not _certificate_matches_hostname(certificate, "notgithub.com")

    def test_get_common_names(self):
        assert get_common_names(certificate.subject) == ["github.com"]

    def test_get_dns_subject_alternative_names(self):
        assert extract_dns_subject_alternative_names(certificate) == ["github.com", "www.github.com"]

    def test_get_name_as_short_text(self):
        assert _get_name_as_short_text(certificate.issuer) == "DigiCert SHA2 Extended Validation Server CA"

    def test_get_public_key_sha256(self):
        assert get_public_key_sha256(certificate)
