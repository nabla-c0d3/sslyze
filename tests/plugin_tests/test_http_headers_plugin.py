# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import logging
import unittest
import pickle

from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.http_headers_plugin import HttpHeadersPlugin, HttpHeadersScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationServerConfigurationEnum, ClientAuthenticationCredentials
from tests.openssl_server import VulnerableOpenSslServer, NotOnLinux64Error


class HttpHeadersPluginTestCase(unittest.TestCase):

    def test_hsts_enabled(self):
        server_test = ServerConnectivityTester(hostname='hsts.badssl.com')
        server_info = server_test.perform()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        self.assertTrue(plugin_result.hsts_header)
        self.assertFalse(plugin_result.hpkp_header)
        self.assertIsNone(plugin_result.is_valid_pin_configured)
        self.assertIsNone(plugin_result.is_backup_pin_configured)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_hsts_and_hpkp_disabled(self):
        server_test = ServerConnectivityTester(hostname='expired.badssl.com')
        server_info = server_test.perform()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        self.assertFalse(plugin_result.hsts_header)
        self.assertFalse(plugin_result.hpkp_header)
        self.assertIsNone(plugin_result.is_valid_pin_configured)
        self.assertIsNone(plugin_result.is_backup_pin_configured)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_hpkp_enabled(self):
        # HPKP is being deprecated in Chrome - I couldn't find a website with the header set
        pass

    def test_expect_ct_disabled(self):
        server_test = ServerConnectivityTester(hostname='hsts.badssl.com')
        server_info = server_test.perform()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        self.assertFalse(plugin_result.expect_ct_header)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        self.assertTrue(pickle.dumps(plugin_result))

    def test_expect_ct_enabled(self):
        # Github was the only server I could find with expect-ct header set
        server_test = ServerConnectivityTester(hostname='github.com')
        server_info = server_test.perform()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        self.assertTrue(plugin_result.expect_ct_header)
        self.assertTrue(plugin_result.expect_ct_header.max_age >= 0)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        self.assertTrue(pickle.dumps(plugin_result))

    def test_fails_when_client_auth_failed(self):
        # Given a server that requires client authentication
        try:
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

                # The plugin fails when a client cert was not supplied
                plugin = HttpHeadersPlugin()
                with self.assertRaises(ClientCertificateRequested):
                    plugin.process_task(server_info, HttpHeadersScanCommand())

        except NotOnLinux64Error:
            logging.warning('WARNING: Not on Linux - skipping test')
            return

    def test_works_when_client_auth_succeeded(self):
        # Given a server that requires client authentication
        try:
            with VulnerableOpenSslServer(
                    client_auth_config=ClientAuthenticationServerConfigurationEnum.REQUIRED
            ) as server:
                # And the client provides a client certificate
                client_creds = ClientAuthenticationCredentials(
                    client_certificate_chain_path=server.get_client_certificate_path(),
                    client_key_path=server.get_client_key_path(),
                )

                server_test = ServerConnectivityTester(
                    hostname=server.hostname,
                    ip_address=server.ip_address,
                    port=server.port,
                    client_auth_credentials=client_creds,
                )
                server_info = server_test.perform()

                # The plugin works fine
                plugin = HttpHeadersPlugin()
                plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        except NotOnLinux64Error:
            logging.warning('WARNING: Not on Linux - skipping test')
            return

        self.assertIsNone(plugin_result.expect_ct_header)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
