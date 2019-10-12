import threading

import pytest

from sslyze.server_connectivity_tester import ServerConnectivityTester, ClientAuthenticationServerConfigurationEnum, \
    HttpProxyConnectivityError
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection, ServerNetworkLocationViaHttpProxy, \
    HttpProxySettings
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum, LegacyOpenSslServer
from tests.tiny_proxy import ThreadingHTTPServer, ProxyHandler


class TestServerConnectivityTester:

    def test_via_direct_connection(self):
        # Given a server location
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)

        # When testing connectivity
        server_info = ServerConnectivityTester().perform(server_location)

        # It succeeds
        assert server_info.tls_probing_result.openssl_cipher_string_supported
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.client_auth_requirement

    def test_via_direct_connection_but_server_offline(self):
        # Given a server location for a server that's offline
        server_location = ServerNetworkLocationViaDirectConnection(
            "notarealdomain.not.real.notreal.not", 1234, "123.123.123.123"
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(HttpProxyConnectivityError):
            ServerConnectivityTester().perform(server_location)

    def test_via_http_proxy(self):
        # Given a server location configured with a proxy
        proxy_port = 8123
        proxy_server = ThreadingHTTPServer(("", proxy_port), ProxyHandler)
        proxy_server_thread = threading.Thread(target=proxy_server.serve_forever)
        proxy_server_thread.start()

        # When testing connectivity
        try:
            proxy_settings = HttpProxySettings("localhost", proxy_port)
            server_location = ServerNetworkLocationViaHttpProxy("www.google.com", 443, proxy_settings)

            server_info = ServerConnectivityTester().perform(server_location)
        finally:
            proxy_server.shutdown()

        # It succeeds
        assert server_info.tls_probing_result.openssl_cipher_string_supported
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.client_auth_requirement

    def test_via_http_proxy_but_proxy_offline(self):
        # Given a server location configured with a proxy that's offline
        proxy_settings = HttpProxySettings("notarealdomain.not.real.notreal.not", 1234)
        server_location = ServerNetworkLocationViaHttpProxy("www.google.com", 443, proxy_settings)

        # When testing connectivity, it fails with the right error
        with pytest.raises(HttpProxyConnectivityError):
            ServerConnectivityTester().perform(server_location)


class TestConnectivityTesterClientAuthRequirementDetection:

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
