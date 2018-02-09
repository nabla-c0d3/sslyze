# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest
import logging

from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionPlugin, OpenSslCcsInjectionScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from tests import SslyzeTestCase
from tests.plugin_tests.openssl_server import VulnerableOpenSslServer, NOT_ON_LINUX_64BIT


class OpenSslCcsInjectionPluginTestCase(unittest.TestCase):

    def test_ccs_injection_good(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCcsInjectionPlugin()
        plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())

        self.assertFalse(plugin_result.is_vulnerable_to_ccs_injection)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    @unittest.skipIf(NOT_ON_LINUX_64BIT,
                     'test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits')
    def test_ccs_injection_bad(self):
        with VulnerableOpenSslServer() as server:
            server_info = ServerConnectivityInfo(hostname=server.hostname, ip_address=server.ip_address,
                                                 port=server.port)
            server_info.test_connectivity_to_server()

            plugin = OpenSslCcsInjectionPlugin()
            plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())

        self.assertTrue(plugin_result.is_vulnerable_to_ccs_injection)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

