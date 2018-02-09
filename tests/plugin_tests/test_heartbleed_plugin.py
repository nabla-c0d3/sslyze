# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

import pickle
import unittest

from sslyze.plugins.heartbleed_plugin import HeartbleedPlugin, HeartbleedScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo

from tests.plugin_tests.openssl_server import NOT_ON_LINUX_64BIT
from tests.plugin_tests.openssl_server import VulnerableOpenSslServer


class HeartbleedPluginTestCase(unittest.TestCase):

    def test_heartbleed_good(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = HeartbleedPlugin()
        plugin_result = plugin.process_task(server_info, HeartbleedScanCommand())

        self.assertFalse(plugin_result.is_vulnerable_to_heartbleed)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    @unittest.skipIf(NOT_ON_LINUX_64BIT,
                     'test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits')
    def test_heartbleed_bad(self):
        with VulnerableOpenSslServer() as server:
            server_info = ServerConnectivityInfo(hostname=server.hostname, ip_address=server.ip_address,
                                                 port=server.port)
            server_info.test_connectivity_to_server()

            plugin = HeartbleedPlugin()
            plugin_result = plugin.process_task(server_info, HeartbleedScanCommand())

        self.assertTrue(plugin_result.is_vulnerable_to_heartbleed)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

