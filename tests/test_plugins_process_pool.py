import unittest
from sslyze.plugins_finder import PluginsFinder
from sslyze.plugins_process_pool import PluginsProcessPool
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
        plugins_process_pool.queue_plugin_task(server_info, 'certinfo_basic')
        plugins_process_pool.queue_plugin_task(server_info, 'reneg')
        plugins_process_pool.queue_plugin_task(server_info, 'compression')

        # Process the results
        nb_results = 0
        for plugin_result in plugins_process_pool.get_results():
            self.assertTrue(plugin_result.as_text())
            self.assertTrue(plugin_result.as_xml())
            nb_results +=1

        self.assertEquals(nb_results, 3)