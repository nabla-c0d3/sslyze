# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

import logging

import pickle

from sslyze.plugins.fallback_scsv_plugin import FallbackScsvPlugin, FallbackScsvScanCommand
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.server_connectivity_tester import ServerConnectivityTester
from tests.openssl_server import NotOnLinux64Error
from tests.openssl_server import VulnerableOpenSslServer


class FallbackScsvPluginTestCase(unittest.TestCase):

    def test_fallback_good(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = FallbackScsvPlugin()
        plugin_result = plugin.process_task(server_info, FallbackScsvScanCommand())

        self.assertTrue(plugin_result.supports_fallback_scsv)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_fallback_bad(self):
        try:
            with VulnerableOpenSslServer() as server:
                server_test = ServerConnectivityTester(hostname=server.hostname, ip_address=server.ip_address,
                                                         port=server.port)
                server_info = server_test.perform()

                plugin = FallbackScsvPlugin()
                plugin_result = plugin.process_task(server_info, FallbackScsvScanCommand())
        except NotOnLinux64Error:
            # The test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits
            logging.warning('WARNING: Not on Linux - skipping test_fallback_bad() test')
            return

        self.assertFalse(plugin_result.supports_fallback_scsv)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))
