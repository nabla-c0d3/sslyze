import threading

import pytest

from sslyze.server_connectivity_tester import ServerConnectivityTester, ClientAuthenticationServerConfigurationEnum
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection, ServerNetworkLocationViaHttpProxy, \
    HttpProxySettings
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum, LegacyOpenSslServer
from tests.tiny_proxy import ThreadingHTTPServer, ProxyHandler


class TestServerConnectivityTester:

    def test_via_direct_connection(self):
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)

        # TODO(AD): Better name?
        server_info = ServerConnectivityTester().perform(server_location)

        assert server_info.tls_probing_result.openssl_cipher_string_supported
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.client_auth_requirement

    def test_via_http_proxy(self):
        proxy_port = 8123
        proxy_server = ThreadingHTTPServer(("", proxy_port), ProxyHandler)
        proxy_server_thread = threading.Thread(target=proxy_server.serve_forever)
        proxy_server_thread.start()

        try:
            proxy_settings = HttpProxySettings("localhost", proxy_port)
            server_location = ServerNetworkLocationViaHttpProxy("www.google.com", 443, proxy_settings)

            server_info = ServerConnectivityTester().perform(server_location)
        finally:
            proxy_server.shutdown()

        assert server_info.tls_probing_result.openssl_cipher_string_supported
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.client_auth_requirement


class TestServerConnectivityTesterClientAuthRequirementDetection:

    @can_only_run_on_linux_64
    def test_optional_client_auth(self):
        # Given a server that supports optional client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.OPTIONAL) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname,
                port=server.port,
                ip_address=server.ip_address,
            )
            server_info = ServerConnectivityTester().perform(server_location)

        # SSLyze correctly detects that client auth is optional
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.OPTIONAL

    @can_only_run_on_linux_64
    def test_required_client_auth_tls_1_2(self):
        # Given a TLS 1.2 server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname,
                port=server.port,
                ip_address=server.ip_address,
            )

            server_info = ServerConnectivityTester().perform(server_location)

        # SSLyze correctly detects that client auth is required
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.REQUIRED

    @pytest.mark.skip(msg="Client auth config detection with TLS 1.3 is broken; fix me")
    @can_only_run_on_linux_64
    def test_required_client_auth_tls_1_3(self):
        # Given a TLS 1.3 server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname,
                port=server.port,
                ip_address=server.ip_address,
            )

            server_info = ServerConnectivityTester().perform(server_location)

        # SSLyze correctly detects that client auth is required
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.REQUIRED
