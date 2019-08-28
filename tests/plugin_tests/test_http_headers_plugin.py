import pickle

from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.http_headers_plugin import HttpHeadersPlugin, HttpHeadersScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationCredentials
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum, LegacyOpenSslServer
import pytest


class TestHttpHeadersPlugin:

    def test_hsts_enabled(self):
        server_test = ServerConnectivityTester(hostname='hsts.badssl.com')
        server_info = server_test.perform()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        assert plugin_result.strict_transport_security_header
        assert not plugin_result.public_key_pins_header
        assert plugin_result.is_valid_pin_configured is None
        assert plugin_result.is_backup_pin_configured is None

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    def test_hsts_and_hpkp_disabled(self):
        server_test = ServerConnectivityTester(hostname='expired.badssl.com')
        server_info = server_test.perform()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        assert not plugin_result.strict_transport_security_header
        assert not plugin_result.public_key_pins_header
        assert plugin_result.is_valid_pin_configured is None
        assert plugin_result.is_backup_pin_configured is None

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    def test_hpkp_enabled(self):
        # HPKP is being deprecated in Chrome - I couldn't find a website with the header set
        pass

    def test_expect_ct_disabled(self):
        server_test = ServerConnectivityTester(hostname='hsts.badssl.com')
        server_info = server_test.perform()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        assert not plugin_result.expect_ct_header

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        assert pickle.dumps(plugin_result)

    def test_expect_ct_enabled(self):
        # Github was the only server I could find with expect-ct header set
        server_test = ServerConnectivityTester(hostname='github.com')
        server_info = server_test.perform()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        assert plugin_result.expect_ct_header
        assert plugin_result.expect_ct_header.max_age >= 0

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        assert pickle.dumps(plugin_result)

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed_tls_1_2(self):
        # Given a server with TLS 1.2 that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client does NOT provide a client certificate
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            # The plugin fails when a client cert was not supplied
            plugin = HttpHeadersPlugin()
            with pytest.raises(ClientCertificateRequested):
                plugin.process_task(server_info, HttpHeadersScanCommand())

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed_tls_1_3(self):
        # Given a server with TLS 1.3 that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client does NOT provide a client certificate
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            # The plugin fails when a client cert was not supplied
            plugin = HttpHeadersPlugin()
            with pytest.raises(ClientCertificateRequested):
                plugin.process_task(server_info, HttpHeadersScanCommand())

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

            # The plugin works fine
            plugin = HttpHeadersPlugin()
            plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        assert plugin_result.expect_ct_header is None
        assert plugin_result.as_text()
        assert plugin_result.as_xml()

    def test_legacy_ssl_client_missing_verified_chain(self):
        # Given a tls1.0 server
        server_test = ServerConnectivityTester(hostname='tls-v1-0.badssl.com', port=1010)
        server_info = server_test.perform()

        # The plugin does not throw an exception trying to access LegacySslClient.get_verified_chain()
        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        assert plugin_result.as_text()
        assert plugin_result.as_xml()
