import pytest

from sslyze.plugins.compression_plugin import CompressionImplementation, CompressionScanResult
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


class TestCompressionPlugin:
    def test_compression_disabled(self):
        # Given a server to scan that has TLS compression disabled
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When testing for compression support, it succeeds
        result: CompressionScanResult = CompressionImplementation.scan_server(server_info)

        # And the right result is returned
        assert not result.supports_compression

        # And a CLI output can be generated
        assert CompressionImplementation.cli_connector_cls.result_to_console_output(result)

    @pytest.mark.skip("Not implemented; find a server vulnerable to TLS compression")
    def test_compression_enabled(self):
        # TODO
        pass

    @can_only_run_on_linux_64
    def test_succeeds_when_client_auth_failed(self):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for compression support, it succeeds
            result: CompressionScanResult = CompressionImplementation.scan_server(server_info)

        assert not result.supports_compression
