import threading

import pytest

from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaHttpProxy, HttpProxySettings
from sslyze.errors import (
    ConnectionToHttpProxyTimedOut,
    ConnectionToHttpProxyFailed,
    HttpProxyRejectedConnection,
)
from tests.server_connectivity_tests.tiny_proxy import ThreadingHTTPServer, ProxyHandler


class TestServerConnectivityTesterWithProxy:
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
            http_proxy_settings=HttpProxySettings("localhost", proxy_port),
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
            http_proxy_settings=HttpProxySettings("notarealdomain.not.real.notreal.not", 443),
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
            http_proxy_settings=HttpProxySettings("1.2.3.4", 80),
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
            http_proxy_settings=HttpProxySettings("localhost", 1234),
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
            http_proxy_settings=HttpProxySettings("www.hotmail.com", 443),
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ConnectionToHttpProxyTimedOut):
            ServerConnectivityTester().perform(server_location)
