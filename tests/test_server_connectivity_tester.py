import threading

import pytest

from sslyze.server_connectivity_tester import ServerConnectivityTester, ClientAuthRequirementEnum
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection, ServerNetworkLocationViaHttpProxy, \
    HttpProxySettings
from sslyze.utils.connection_errors import ConnectionToServerTimedOut, ConnectionToHttpProxyTimedOut, \
    ConnectionToHttpProxyFailed, HttpProxyRejectedConnection, ServerRejectedConnection
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
        assert server_info.tls_probing_result.cipher_suite_supported
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.get_preconfigured_tls_connection()

    def test_via_direct_connection_but_server_timed_out(self):
        # Given a server location for a server that's offline
        server_location = ServerNetworkLocationViaDirectConnection(
            hostname="notarealdomain.not.real.notreal.not",
            port=1234,
            ip_address="123.123.123.123",
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ConnectionToServerTimedOut):
            ServerConnectivityTester().perform(server_location)

    def test_via_direct_connection_but_server_rejected_connection(self):
        # Given a server location for a server that's offline
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname="localhost",
            port=1234,
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ServerRejectedConnection):
            ServerConnectivityTester().perform(server_location)

    def test_via_http_proxy(self):
        # Given an HTTP proxy
        proxy_port = 8123
        proxy_server = ThreadingHTTPServer(("", proxy_port), ProxyHandler)
        proxy_server_thread = threading.Thread(target=proxy_server.serve_forever)
        proxy_server_thread.start()

        # And a server location
        server_location = ServerNetworkLocationViaHttpProxy(
            hostname="www.google.com",
            port=443,
            # Configured with this proxy
            http_proxy_settings=HttpProxySettings("localhost", proxy_port)
        )

        # When testing connectivity
        try:
            server_info = ServerConnectivityTester().perform(server_location)
        finally:
            proxy_server.shutdown()

        # It succeeds
        assert server_info.tls_probing_result.cipher_suite_supported
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.get_preconfigured_tls_connection()

    def test_via_http_proxy_but_proxy_dns_error(self):
        # Given a server location
        server_location = ServerNetworkLocationViaHttpProxy(
            hostname="www.google.com",
            port=443,
            # Configured with a proxy that cannot be looked up via DNS
            http_proxy_settings=HttpProxySettings("notarealdomain.not.real.notreal.not", 443)
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ConnectionToHttpProxyFailed):
            ServerConnectivityTester().perform(server_location)

    def test_via_http_proxy_but_proxy_timed_out(self):
        # Given a server location
        server_location = ServerNetworkLocationViaHttpProxy(
            hostname="www.google.com",
            port=443,
            # Configured with a proxy that will time out
            http_proxy_settings=HttpProxySettings("www.hotmail.com", 1234)
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ConnectionToHttpProxyTimedOut):
            ServerConnectivityTester().perform(server_location)

    def test_via_http_proxy_but_proxy_rejected_connection(self):
        # Given a server location
        server_location = ServerNetworkLocationViaHttpProxy(
            hostname="www.google.com",
            port=443,
            # Configured with a proxy that's offline
            http_proxy_settings=HttpProxySettings("localhost", 1234)
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(HttpProxyRejectedConnection):
            ServerConnectivityTester().perform(server_location)

    def test_via_http_proxy_but_proxy_rejected_http_connect(self):
        # Given a server location
        server_location = ServerNetworkLocationViaHttpProxy(
            hostname="www.google.com",
            port=443,
            # Configured with a proxy that is going to reject the HTTP CONNECT request
            http_proxy_settings=HttpProxySettings("www.hotmail.com", 443)
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ConnectionToHttpProxyTimedOut):
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
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.OPTIONAL

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
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.REQUIRED

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
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.REQUIRED
