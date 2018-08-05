import unittest

import pickle

from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationPlugin, SessionRenegotiationScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationCredentials
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


class SessionRenegotiationPluginTestCase(unittest.TestCase):

    def test_renegotiation_good(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = SessionRenegotiationPlugin()
        plugin_result = plugin.process_task(server_info, SessionRenegotiationScanCommand())

        self.assertFalse(plugin_result.accepts_client_renegotiation)
        self.assertTrue(plugin_result.supports_secure_renegotiation)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    @unittest.skipIf(not LegacyOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_fails_when_client_auth_failed_session(self):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client does NOT provide a client certificate
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()


            # The plugin fails when a client cert was not supplied
            plugin = SessionRenegotiationPlugin()
            with self.assertRaises(ClientCertificateRequested):
                plugin.process_task(server_info, SessionRenegotiationScanCommand())

    @unittest.skipIf(not LegacyOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_works_when_client_auth_succeeded(self):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
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
            plugin = SessionRenegotiationPlugin()
            plugin_result = plugin.process_task(server_info, SessionRenegotiationScanCommand())

        self.assertTrue(plugin_result.accepts_client_renegotiation)
        self.assertTrue(plugin_result.supports_secure_renegotiation)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
