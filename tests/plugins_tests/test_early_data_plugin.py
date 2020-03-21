from sslyze.plugins.early_data_plugin import EarlyDataScanResult, EarlyDataImplementation
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, LegacyOpenSslServer


class TestEarlyDataPlugin:
    @can_only_run_on_linux_64
    def test_early_data_enabled(self):
        # Given a server to scan that supports early data
        with ModernOpenSslServer(max_early_data=256) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for early data support, it succeeds
            result: EarlyDataScanResult = EarlyDataImplementation.scan_server(server_info)

        # And the right result is returned
        assert result.supports_early_data

        # And a CLI output can be generated
        assert EarlyDataImplementation.cli_connector_cls.result_to_console_output(result)

    @can_only_run_on_linux_64
    def test_early_data_disabled_no_tls_1_3(self):
        # Given a server to scan that does NOT support early data because it does not support TLS 1.3
        with LegacyOpenSslServer() as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for early data support, it succeeds
            result: EarlyDataScanResult = EarlyDataImplementation.scan_server(server_info)

        # And the right result is returned
        assert not result.supports_early_data

    @can_only_run_on_linux_64
    def test_early_data_disabled(self):
        # Given a server to scan that does NOT support early data because it it is disabled
        with ModernOpenSslServer(max_early_data=None) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for early data support, it succeeds
            result: EarlyDataScanResult = EarlyDataImplementation.scan_server(server_info)

            # And the right result is returned
        assert not result.supports_early_data
