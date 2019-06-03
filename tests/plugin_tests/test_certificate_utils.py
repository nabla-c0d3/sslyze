import ssl
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from sslyze.plugins.utils.certificate_utils import CertificateUtils
import pytest


class TestCertificateUtils:

    def test(self):
        leaf_path = Path(__file__).absolute().parent / '..' / 'utils' / 'github.com.pem'
        leaf_pem = leaf_path.read_bytes()
        certificate = load_pem_x509_certificate(leaf_pem, default_backend())

        assert CertificateUtils.matches_hostname(certificate, 'www.github.com') is None

        with pytest.raises(ssl.CertificateError):
            assert not CertificateUtils.matches_hostname(certificate, 'notgithub.com')

        assert CertificateUtils.get_common_names(certificate.subject) == ['github.com']
        assert CertificateUtils.get_dns_subject_alternative_names(certificate) == [
            'github.com', 'www.github.com'
        ]

        expected_name = 'DigiCert SHA2 Extended Validation Server CA'
        assert CertificateUtils.get_name_as_short_text(certificate.issuer) == expected_name
