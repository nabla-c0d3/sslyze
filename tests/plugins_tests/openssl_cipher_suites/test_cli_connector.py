from sslyze.plugins.openssl_cipher_suites.implementation import Tlsv12ScanImplementation
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection


class TestCipherSuitesCliConnector:
    def test(self):
        # Given a completed scan for a cipher suites scan command
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)
        plugin_result = Tlsv12ScanImplementation.scan_server(server_info)

        # When generating the CLI output for this result, it succeeds
        result_as_txt = Tlsv12ScanImplementation.cli_connector_cls.result_to_console_output(plugin_result)
        assert result_as_txt
