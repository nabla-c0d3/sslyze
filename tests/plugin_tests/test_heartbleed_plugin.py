# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

import logging

from sslyze.plugins.heartbleed_plugin import HeartbleedPlugin, HeartbleedScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo

from tests.plugin_tests.openssl_server import NotOnLinux64Error
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

    def test_heartbleed_bad(self):
        try:
            server = VulnerableOpenSslServer(port=8011)
        except NotOnLinux64Error:
            # The test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits
            logging.warning('WARNING: Not on Linux - skipping test_heartbleed_bad() test')
            return

        server.start()
        server_info = ServerConnectivityInfo(hostname=server.hostname, ip_address=server.ip_address,  port=server.port)
        server_info.test_connectivity_to_server()

        plugin = HeartbleedPlugin()
        plugin_result = plugin.process_task(server_info, HeartbleedScanCommand())
        server.terminate()

        self.assertTrue(plugin_result.is_vulnerable_to_heartbleed)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

