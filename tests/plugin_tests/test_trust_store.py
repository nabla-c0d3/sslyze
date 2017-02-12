import os
import unittest

from sslyze.plugins.utils.certificate import Certificate
from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository


class TrustStoreTestCase(unittest.TestCase):

    def test(self):
        intermediate_path = os.path.join(os.path.dirname(__file__), u'..', u'utils',
                                         u'DigiCertSHA2ExtendedValidationServerCA.pem')
        with open(intermediate_path) as intermediate_file:
            intermediate_pem = intermediate_file.read()

        leaf_path = os.path.join(os.path.dirname(__file__), u'..', u'utils', u'github.com.pem')
        with open(leaf_path) as leaf_file:
            leaf_pem = leaf_file.read()

        certificate_chain = [Certificate.from_pem(leaf_pem), Certificate.from_pem(intermediate_pem)]

        for trust_store in TrustStoresRepository.get_all():
            verified_chain = trust_store.build_verified_certificate_chain(certificate_chain)
            self.assertTrue(verified_chain)
