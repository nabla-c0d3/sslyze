from sslyze.plugins.openssl_cipher_suites.cli_connector import CliConnector
from sslyze.plugins.openssl_cipher_suites.scan_commands import Tlsv10ScanCommand, \
    Tlsv11ScanCommand
from sslyze.scanner import Scanner
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationThroughDirectConnection, ServerTlsConfiguration


# TODO: Finish this
class TestScanner:

    def test(self):
        server_location = ServerNetworkLocationThroughDirectConnection.with_ip_address_lookup("www.google.com", 443)
        tls_config = ServerTlsConfiguration.get_default("www.google.com")

        server_test = ServerConnectivityTester()
        server_info = server_test.perform(server_location, tls_config)

        print(server_info)

        scanner = Scanner()
        scanner.queue_scan_command(Tlsv10ScanCommand(server_info))
        scanner.queue_scan_command(Tlsv11ScanCommand(server_info))
        for result in scanner.get_results():
            for line in CliConnector(hide_rejected_ciphers=False).print_result(result):
                print(line)
            pass
        raise Exception()
