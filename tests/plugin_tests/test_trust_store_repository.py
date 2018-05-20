import unittest

from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository


class TrustStoresRepositoryTestCase(unittest.TestCase):

    def test_get_default(self):
        repo = TrustStoresRepository.get_default()
        self.assertTrue(repo.get_main_store())
        self.assertGreater(len(repo.get_all_stores()), 5)

    def test_update_default(self):
        repo = TrustStoresRepository.update_default()
        self.assertTrue(repo.get_main_store())
        self.assertGreater(len(repo.get_all_stores()), 5)
