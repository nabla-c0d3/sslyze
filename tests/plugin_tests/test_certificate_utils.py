# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import ssl
from tests import SslyzeTestCase

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from sslyze.plugins.utils.certificate_utils import CertificateUtils


class CertificateUtilsTestCase(SslyzeTestCase):

    def test(self):
        leaf_path = os.path.join(os.path.dirname(__file__), '..', 'utils', 'github.com.pem')
        with open(leaf_path, 'rb') as leaf_file:
            leaf_pem = leaf_file.read()

        certificate = load_pem_x509_certificate(leaf_pem, default_backend())

        self.assertIsNone(CertificateUtils.matches_hostname(certificate, 'www.github.com'))
        with self.assertRaises(ssl.CertificateError):
            self.assertFalse(CertificateUtils.matches_hostname(certificate, 'notgithub.com'))

        self.assertEqual(CertificateUtils.get_common_names(certificate.subject), ['github.com'])
        self.assertEqual(CertificateUtils.get_dns_subject_alternative_names(certificate), ['github.com',
                                                                                           'www.github.com'])

        self.assertEqual(CertificateUtils.get_name_as_short_text(certificate.issuer),
                         'DigiCert SHA2 Extended Validation Server CA')

