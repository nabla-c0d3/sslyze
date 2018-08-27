import os
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate
from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository


class TrustStoreTestCase(unittest.TestCase):

    def test(self):
        intermediate_path = os.path.join(os.path.dirname(__file__), '..', 'utils',
                                         'DigiCertSHA2ExtendedValidationServerCA.pem')
        with open(intermediate_path) as intermediate_file:
            intermediate_pem = intermediate_file.read().encode('ascii')

        leaf_path = os.path.join(os.path.dirname(__file__), '..', 'utils', 'github.com.pem')
        with open(leaf_path) as leaf_file:
            leaf_pem = leaf_file.read().encode('ascii')

        certificate_chain = [load_pem_x509_certificate(leaf_pem, default_backend()),
                             load_pem_x509_certificate(intermediate_pem, default_backend())]

        found_mozilla = False
        for trust_store in TrustStoresRepository.get_default().get_all_stores():
            verified_chain = trust_store.build_verified_certificate_chain(certificate_chain)
            self.assertTrue(verified_chain)
            if trust_store.name == 'Mozilla':
                found_mozilla = True
                # The GH certificate is EV
                self.assertTrue(trust_store.is_extended_validation(certificate_chain[0]))

        self.assertTrue(found_mozilla)
