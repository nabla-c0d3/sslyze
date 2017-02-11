import unittest

from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.compression_plugin import CompressionScanCommand
from sslyze.plugins.plugins_repository import PluginsFinder
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from sslyze.concurrent_scanner import PluginsProcessPool
from sslyze.server_connectivity import ServerConnectivityInfo


class PluginsProcessPoolTestCase(unittest.TestCase):

    def test_plugin_process_pool(self):
        server_info = ServerConnectivityInfo(hostname=u'www.google.com')
        server_info.test_connectivity_to_server()

        # Get the list of available plugins
        sslyze_plugins = PluginsFinder.get()

        # Create a process pool to run scanning commands concurrently
        plugins_process_pool = PluginsProcessPool(sslyze_plugins)

        # Queue some scan commands that are quick
        plugins_process_pool.queue_plugin_task(server_info, CertificateInfoScanCommand())
        plugins_process_pool.queue_plugin_task(server_info, SessionRenegotiationScanCommand())
        plugins_process_pool.queue_plugin_task(server_info, CompressionScanCommand())

        # Process the results
        nb_results = 0
        for plugin_result in plugins_process_pool.get_results():
            self.assertTrue(plugin_result.as_text())
            self.assertTrue(plugin_result.as_xml())
            nb_results +=1

        self.assertEquals(nb_results, 3)