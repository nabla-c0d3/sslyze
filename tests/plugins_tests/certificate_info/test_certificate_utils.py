import ssl
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
import pytest

from sslyze.plugins.certificate_info.certificate_utils import CertificateUtils


leaf_path = Path(__file__).absolute().parent / ".." / ".." / "certificates" / "github.com.pem"
leaf_pem = leaf_path.read_bytes()
certificate = load_pem_x509_certificate(leaf_pem, default_backend())


class TestCertificateUtils:
    def test_certificate_matches_hostname_good_hostname(self):
        assert CertificateUtils.certificate_matches_hostname(certificate, "www.github.com") is None

    def test_certificate_matches_hostname_bad_hostname(self):
        with pytest.raises(ssl.CertificateError):
            assert not CertificateUtils.certificate_matches_hostname(certificate, "notgithub.com")

    def test_get_common_names(self):
        assert CertificateUtils.get_common_names(certificate.subject) == ["github.com"]

    def test_get_dns_subject_alternative_names(self):
        assert CertificateUtils.get_dns_subject_alternative_names(certificate) == ["github.com", "www.github.com"]

    def test_get_name_as_short_text(self):
        assert (
            CertificateUtils.get_name_as_short_text(certificate.issuer) == "DigiCert SHA2 Extended Validation Server CA"
        )

    def test_get_hpkp_pin(self):
        assert CertificateUtils.get_hpkp_pin(certificate) == "pL1+qb9HTMRZJmuC/bB/ZI9d302BYrrqiVuRyW+DGrU="
