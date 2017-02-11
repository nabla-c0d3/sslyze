import unittest
from sslyze.plugins.http_headers_plugin import HttpHeadersPlugin, HttpHeadersPluginScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo


class HttpHeadersPluginTestCase(unittest.TestCase):

    def test_hsts_enabled(self):
        server_info = ServerConnectivityInfo(hostname=u'hsts.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersPluginScanCommand())

        self.assertTrue(plugin_result.hsts_header)
        self.assertFalse(plugin_result.hpkp_header)
        self.assertIsNone(plugin_result.is_valid_pin_configured)
        self.assertIsNone(plugin_result.is_backup_pin_configured)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_hsts_and_hpkp_disabled(self):
        server_info = ServerConnectivityInfo(hostname=u'expired.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersPluginScanCommand())

        self.assertFalse(plugin_result.hsts_header)
        self.assertFalse(plugin_result.hpkp_header)
        self.assertIsNone(plugin_result.is_valid_pin_configured)
        self.assertIsNone(plugin_result.is_backup_pin_configured)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_hpkp_enabled(self):
        server_info = ServerConnectivityInfo(hostname=u'github.com')
        server_info.test_connectivity_to_server()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersPluginScanCommand())

        self.assertTrue(plugin_result.hpkp_header)
        self.assertTrue(plugin_result.is_valid_pin_configured)
        self.assertTrue(plugin_result.is_backup_pin_configured)
        self.assertTrue(plugin_result.verified_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
