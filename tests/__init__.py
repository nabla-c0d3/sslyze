import unittest

from sslyze.utils.ssl_connection import SSLConnection
from sslyze.synchronous_scanner import SynchronousScanner

class SslyzeTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        SSLConnection.set_global_network_settings(
            network_max_retries=3,
            network_timeout=10
        )

    @classmethod
    def tearDownClass(cls):
        SSLConnection.set_global_network_settings(
            network_max_retries=SynchronousScanner.DEFAULT_NETWORK_RETRIES,
            network_timeout=SynchronousScanner.DEFAULT_NETWORK_TIMEOUT
        )
