# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

import pickle

from sslyze.plugins.compression_plugin import CompressionPlugin, CompressionScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo


class CompressionPluginTestCase(unittest.TestCase):

    def test_compression_disabled(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = CompressionPlugin()
        plugin_result = plugin.process_task(server_info, CompressionScanCommand())

        self.assertFalse(plugin_result.compression_name)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_compression_enabled(self):
        # TBD - need to find a host that has compression enabled?
        pass