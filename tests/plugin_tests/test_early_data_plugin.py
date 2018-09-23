import unittest

import pickle

from sslyze.plugins.early_data_plugin import EarlyDataPlugin, EarlyDataScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from tests.openssl_server import ModernOpenSslServer, LegacyOpenSslServer


class EarlyDataPluginTestCase(unittest.TestCase):

    @unittest.skipIf(not ModernOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_early_data_enabled(self):
        with ModernOpenSslServer(max_early_data=256) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            plugin = EarlyDataPlugin()
            plugin_result = plugin.process_task(server_info, EarlyDataScanCommand())

        self.assertTrue(plugin_result.is_early_data_supported)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_early_data_enabled_online(self):
        server_test = ServerConnectivityTester(hostname='www.cloudflare.com')
        server_info = server_test.perform()

        plugin = EarlyDataPlugin()
        plugin_result = plugin.process_task(server_info, EarlyDataScanCommand())

        self.assertTrue(plugin_result.is_early_data_supported)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    @unittest.skipIf(not LegacyOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_early_data_disabled_no_tls_1_3(self):
        with LegacyOpenSslServer() as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            plugin = EarlyDataPlugin()
            plugin_result = plugin.process_task(server_info, EarlyDataScanCommand())

        self.assertFalse(plugin_result.is_early_data_supported)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    @unittest.skipIf(not ModernOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_early_data_disabled(self):
        with ModernOpenSslServer(max_early_data=None) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            plugin = EarlyDataPlugin()
            plugin_result = plugin.process_task(server_info, EarlyDataScanCommand())

        self.assertFalse(plugin_result.is_early_data_supported)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))
