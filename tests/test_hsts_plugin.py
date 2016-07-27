import unittest
from sslyze.plugins.hsts_plugin import HstsPlugin
from sslyze.server_connectivity import ServerConnectivityInfo


class HstsPluginTestCase(unittest.TestCase):

    def test_hsts_enabled(self):
        server_info = ServerConnectivityInfo(hostname='hsts.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = HstsPlugin()
        plugin_result = plugin.process_task(server_info, 'hsts')

        self.assertTrue(plugin_result.hsts_header)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_hsts_disabled(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = HstsPlugin()
        plugin_result = plugin.process_task(server_info, 'hsts')

        self.assertFalse(plugin_result.hsts_header)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())