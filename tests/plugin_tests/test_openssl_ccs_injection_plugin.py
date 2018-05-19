# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionPlugin, OpenSslCcsInjectionScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationServerConfigurationEnum
from tests.openssl_server import VulnerableOpenSslServer


class OpenSslCcsInjectionPluginTestCase(unittest.TestCase):

    def test_ccs_injection_good(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = OpenSslCcsInjectionPlugin()
        plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())

        self.assertFalse(plugin_result.is_vulnerable_to_ccs_injection)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    @unittest.skipIf(not VulnerableOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_ccs_injection_bad(self):
        with VulnerableOpenSslServer() as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            plugin = OpenSslCcsInjectionPlugin()
            plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())

        self.assertTrue(plugin_result.is_vulnerable_to_ccs_injection)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    @unittest.skipIf(not VulnerableOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_succeeds_when_client_auth_failed(self):
        # Given a server that requires client authentication
        with VulnerableOpenSslServer(
                client_auth_config=ClientAuthenticationServerConfigurationEnum.REQUIRED
        ) as server:
            # And the client does NOT provide a client certificate
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            # OpenSslCcsInjectionPlugin works even when a client cert was not supplied
            plugin = OpenSslCcsInjectionPlugin()
            plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())

        self.assertTrue(plugin_result.is_vulnerable_to_ccs_injection)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
