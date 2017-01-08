import unittest
from sslyze.plugins.heartbleed_plugin import HeartbleedPlugin
from sslyze.server_connectivity import ServerConnectivityInfo


class HeartbleedPluginTestCase(unittest.TestCase):

    def test_heartbleed_good(self):
        server_info = ServerConnectivityInfo(hostname=u'www.google.com')
        server_info.test_connectivity_to_server()

        plugin = HeartbleedPlugin()
        plugin_result = plugin.process_task(server_info, 'heartbleed')

        self.assertFalse(plugin_result.is_vulnerable_to_heartbleed)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_heartbleed_bad(self):
        # TBD
        pass