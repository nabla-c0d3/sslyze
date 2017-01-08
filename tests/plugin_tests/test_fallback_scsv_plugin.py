import unittest
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvPlugin
from sslyze.server_connectivity import ServerConnectivityInfo


class FallbackScsvPluginTestCase(unittest.TestCase):

    def test_fallback_good(self):
        server_info = ServerConnectivityInfo(hostname=u'www.google.com')
        server_info.test_connectivity_to_server()

        plugin = FallbackScsvPlugin()
        plugin_result = plugin.process_task(server_info, 'fallback')

        self.assertTrue(plugin_result.supports_fallback_scsv)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_fallback_bad(self):
        # TBD - need to find a host that does not support fallback?
        pass