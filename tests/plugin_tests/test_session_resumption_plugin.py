# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import logging
import unittest

import pickle

from sslyze.plugins.session_resumption_plugin import SessionResumptionPlugin, SessionResumptionSupportScanCommand, \
    SessionResumptionRateScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationServerConfigurationEnum, ClientAuthenticationCredentials
from tests.openssl_server import VulnerableOpenSslServer, NotOnLinux64Error


class SessionResumptionPluginTestCase(unittest.TestCase):

    def test_resumption_support(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = SessionResumptionPlugin()
        plugin_result = plugin.process_task(server_info, SessionResumptionSupportScanCommand())

        self.assertTrue(plugin_result.is_ticket_resumption_supported)
        self.assertTrue(plugin_result.attempted_resumptions_nb)
        self.assertTrue(plugin_result.successful_resumptions_nb)
        self.assertFalse(plugin_result.errored_resumptions_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_resumption_rate(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = SessionResumptionPlugin()
        plugin_result = plugin.process_task(server_info, SessionResumptionRateScanCommand())

        self.assertTrue(plugin_result.attempted_resumptions_nb)
        self.assertTrue(plugin_result.successful_resumptions_nb)
        self.assertFalse(plugin_result.errored_resumptions_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_fails_when_client_auth_failed_session(self):
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

                # SessionResumptionPlugin fails even when a client cert was not supplied
                plugin = SessionResumptionPlugin()
                plugin_result = plugin.process_task(server_info, SessionResumptionSupportScanCommand())

        except NotOnLinux64Error:
            logging.warning('WARNING: Not on Linux - skipping test')
            return

        # All session resumption attempts returned an error because of client authentication
        self.assertEqual(len(plugin_result.errored_resumptions_list), 5)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

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

                # SessionResumptionPlugin works fine
                plugin = SessionResumptionPlugin()
                plugin_result = plugin.process_task(server_info, SessionResumptionSupportScanCommand())

        except NotOnLinux64Error:
            logging.warning('WARNING: Not on Linux - skipping test')
            return

        self.assertEqual(plugin_result.successful_resumptions_nb, 5)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
