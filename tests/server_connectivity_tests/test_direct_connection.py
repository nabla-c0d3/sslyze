import socket

import pytest

from sslyze.server_connectivity import ServerConnectivityTester, TlsVersionEnum
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from sslyze.connection_helpers.errors import (
    ConnectionToServerTimedOut,
    ServerRejectedConnection,
    ServerTlsConfigurationNotSupported,
)


def _is_ipv6_available() -> bool:
    has_ipv6 = False
    s = socket.socket(socket.AF_INET6)
    try:
        s.connect(("2607:f8b0:4005:804::2004", 443))
        has_ipv6 = True
    except Exception:
        pass
    finally:
        s.close()
    return has_ipv6


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
            hostname="notarealdomain.not.real.notreal.not", port=1234, ip_address="123.123.123.123"
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ConnectionToServerTimedOut):
            ServerConnectivityTester().perform(server_location)

    def test_via_direct_connection_but_server_rejected_connection(self):
        # Given a server location for a server that's offline
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname="localhost", port=1234
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ServerRejectedConnection):
            ServerConnectivityTester().perform(server_location)

    def test_via_direct_connection_but_server_tls_config_not_supported(self):
        # Given a server location for a server that only supports DH settings that SSLyze can't use
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname="dh480.badssl.com", port=443
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ServerTlsConfigurationNotSupported):
            ServerConnectivityTester().perform(server_location)

    def test_tls_1_only(self):
        # Given a server that only supports TLS 1.0
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname="tls-v1-0.badssl.com", port=1010
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.tls_probing_result.cipher_suite_supported

        # And it detected that only TLS 1.0 is supported
        assert server_info.tls_probing_result.highest_tls_version_supported == TlsVersionEnum.TLS_1_0

    @pytest.mark.skipif(not _is_ipv6_available(), reason="IPv6 not available")
    def test_ipv6(self):
        # Given a server accessible via IPv6
        server_location = ServerNetworkLocationViaDirectConnection(
            hostname="www.google.com", port=443, ip_address="2607:f8b0:4005:804::2004"
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.cipher_suite_supported

    def test_international_hostname(self):
        # Given a server with non-ascii characters in its hostname
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname="www.sociétégénérale.com", port=443
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.cipher_suite_supported
