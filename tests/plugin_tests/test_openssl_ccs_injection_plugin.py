# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest
import logging

from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionPlugin, OpenSslCcsInjectionScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo, ClientAuthenticationServerConfigurationEnum
from tests.openssl_server import VulnerableOpenSslServer, NotOnLinux64Error


class OpenSslCcsInjectionPluginTestCase(unittest.TestCase):

    def test_ccs_injection_good(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCcsInjectionPlugin()
        plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())

        self.assertFalse(plugin_result.is_vulnerable_to_ccs_injection)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_ccs_injection_bad(self):
        try:
            with VulnerableOpenSslServer() as server:
                server_info = ServerConnectivityInfo(hostname=server.hostname, ip_address=server.ip_address,
                                                     port=server.port)
                server_info.test_connectivity_to_server()

                plugin = OpenSslCcsInjectionPlugin()
                plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())
        except NotOnLinux64Error:
            logging.warning('WARNING: Not on Linux - skipping test')
            return

        self.assertTrue(plugin_result.is_vulnerable_to_ccs_injection)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_succeeds_when_client_auth_failed(self):
        # Given a server that requires client authentication
        try:
            with VulnerableOpenSslServer(
                    client_auth_config=ClientAuthenticationServerConfigurationEnum.REQUIRED
            ) as server:
                # And the client does NOT provide a client certificate
                server_info = ServerConnectivityInfo(
                    hostname=server.hostname,
                    ip_address=server.ip_address,
                    port=server.port
                )
                server_info.test_connectivity_to_server()

                # OpenSslCcsInjectionPlugin works even when a client cert was not supplied
                plugin = OpenSslCcsInjectionPlugin()
                plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())

        except NotOnLinux64Error:
            logging.warning('WARNING: Not on Linux - skipping test')
            return

        self.assertTrue(plugin_result.is_vulnerable_to_ccs_injection)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
