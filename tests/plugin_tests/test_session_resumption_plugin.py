import pickle

from sslyze.plugins.session_resumption_plugin import SessionResumptionPlugin, SessionResumptionSupportScanCommand, \
    SessionResumptionRateScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationCredentials
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum


class TestSessionResumptionPlugin:

    def test_resumption_support(self):
        server_test = ServerConnectivityTester(hostname='www.facebook.com')
        server_info = server_test.perform()

        plugin = SessionResumptionPlugin()
        plugin_result = plugin.process_task(server_info, SessionResumptionSupportScanCommand())

        assert plugin_result.is_ticket_resumption_supported
        assert plugin_result.attempted_resumptions_nb
        assert plugin_result.successful_resumptions_nb
        assert not plugin_result.errored_resumptions_list

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    def test_resumption_rate(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = SessionResumptionPlugin()
        plugin_result = plugin.process_task(server_info, SessionResumptionRateScanCommand())

        assert plugin_result.attempted_resumptions_nb
        assert plugin_result.successful_resumptions_nb
        assert not plugin_result.errored_resumptions_list

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed_session(self):
        # Given a server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
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

        # All session resumption attempts returned an error because of client authentication
        assert len(plugin_result.errored_resumptions_list) == 5
        assert plugin_result.as_text()
        assert plugin_result.as_xml()

    @can_only_run_on_linux_64
    def test_works_when_client_auth_succeeded(self):
        # Given a server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
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

        assert plugin_result.successful_resumptions_nb == 5
        assert plugin_result.as_text()
        assert plugin_result.as_xml()
