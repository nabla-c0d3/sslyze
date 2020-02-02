from sslyze.plugins.heartbleed_plugin import HeartbleedScanResult, HeartbleedImplementation
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.markers import can_only_run_on_linux_64

from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


class TestHeartbleedPlugin:

    def test_heartbleed_good(self):
        # Given a server that is NOT vulnerable to Heartbleed
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When testing for Heartbleed, it succeeds
        result: HeartbleedScanResult = HeartbleedImplementation.perform(server_info)

        # And the server is reported as not vulnerable
        assert result.is_vulnerable_to_heartbleed

    @can_only_run_on_linux_64
    def test_heartbleed_bad(self):
        # Given a server that is vulnerable to Heartbleed
        with LegacyOpenSslServer() as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for Heartbleed, it succeeds
            result: HeartbleedScanResult = HeartbleedImplementation.perform(server_info)

        # And the server is reported as vulnerable
        assert result.is_vulnerable_to_heartbleed

    @can_only_run_on_linux_64
    def test_succeeds_when_client_auth_failed(self):
        # Given a server that is vulnerable to Heartbleed and that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for Heartbleed, it succeeds
            result: HeartbleedScanResult = HeartbleedImplementation.perform(server_info)

        # And the server is reported as vulnerable
        assert result.is_vulnerable_to_heartbleed
