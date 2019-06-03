import pickle

from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationPlugin, SessionRenegotiationScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationCredentials
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum
import pytest


class TestSessionRenegotiationPlugin:

    def test_renegotiation_good(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = SessionRenegotiationPlugin()
        plugin_result = plugin.process_task(server_info, SessionRenegotiationScanCommand())

        assert not plugin_result.accepts_client_renegotiation
        assert plugin_result.supports_secure_renegotiation

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    @can_only_run_on_linux_64
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
            with pytest.raises(ClientCertificateRequested):
                plugin.process_task(server_info, SessionRenegotiationScanCommand())

    @can_only_run_on_linux_64
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

        assert plugin_result.accepts_client_renegotiation
        assert plugin_result.supports_secure_renegotiation

        assert plugin_result.as_text()
        assert plugin_result.as_xml()
