from io import StringIO

from sslyze.cli import CompletedServerScan
from sslyze.cli.console_output import ConsoleOutputGenerator
from sslyze.server_connectivity_tester import ServerConnectivityError
from sslyze.ssl_settings import HttpConnectTunnelingSettings, ClientAuthenticationServerConfigurationEnum
from tests.cli_tests import MockServerConnectivityInfo, MockPluginScanResult, MockPluginScanCommandOne, \
    MockPluginScanCommandTwo, MockServerConnectivityTester


class TestConsoleOutputGenerator:

    def test_command_line_parsed(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        class FakePlugin1:
            pass

        class FakePlugin2:
            pass

        generator.command_line_parsed({FakePlugin1, FakePlugin2}, None, [])

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly listed the available plugins
        assert 'FakePlugin1' in received_output
        assert 'FakePlugin2' in received_output


    def test_server_connectivity_test_failed(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        failed_scan = ServerConnectivityError(server_info=MockServerConnectivityTester(), error_message='Some érrôr')
        generator.server_connectivity_test_failed(failed_scan)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly listed the connectivity error with unicode
        assert 'unicödeéè.com' in received_output
        assert 'Some érrôr' in received_output
        assert 'discarding corresponding tasks' in received_output


    def test_server_connectivity_test_succeeded(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        server_info = MockServerConnectivityInfo()
        generator.server_connectivity_test_succeeded(server_info)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly listed the online domain
        assert server_info.hostname in received_output
        assert str(server_info.port) in received_output
        assert server_info.ip_address in received_output


    def test_server_connectivity_test_succeeded_with_required_client_auth(self):
        # Test when client authentication is required
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        server_info = MockServerConnectivityInfo(ClientAuthenticationServerConfigurationEnum.REQUIRED)
        generator.server_connectivity_test_succeeded(server_info)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly warned about client authentication
        assert 'Server REQUIRED client authentication' in received_output


    def test_server_connectivity_test_succeeded_with_optional_client_auth(self):
        # Test when client authentication is optional
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        server_info = MockServerConnectivityInfo(ClientAuthenticationServerConfigurationEnum.OPTIONAL)
        generator.server_connectivity_test_succeeded(server_info)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly warned about client authentication
        assert 'Server requested optional client authentication' in received_output


    def test_server_connectivity_test_succeeded_with_http_tunneling(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        # When scanning through a proxy, we do not know the final server's IP address
        # This makes sure the console output properly handles that
        tunneling_settings = HttpConnectTunnelingSettings('ûnicôdé.com', 3128)
        server_info = MockServerConnectivityInfo(http_tunneling_settings=tunneling_settings)

        generator.server_connectivity_test_succeeded(server_info)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly listed the online domain and that it was going through a proxy
        assert server_info.hostname in received_output
        assert str(server_info.port) in received_output
        assert 'Proxy' in received_output
        assert tunneling_settings.hostname in received_output
        assert str(tunneling_settings.port) in received_output


    def test_scans_started(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        generator.scans_started()

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output displayed something
        assert received_output


    def test_server_scan_completed(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        server_info = MockServerConnectivityInfo()
        plugin_result_1 = MockPluginScanResult(server_info, MockPluginScanCommandOne(), 'Plugin ûnicôdé output', None)
        plugin_result_2 = MockPluginScanResult(server_info, MockPluginScanCommandTwo(), 'other plugin Output', None)
        server_scan = CompletedServerScan(server_info, [plugin_result_1, plugin_result_2])
        generator.server_scan_completed(server_scan)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output displayed the server's info
        assert server_info.hostname in received_output.lower()
        assert str(server_info.port) in received_output
        assert server_info.ip_address in received_output.lower()

        # Ensure the console output displayed the plugin text outputs
        assert plugin_result_1.text_output in received_output
        assert plugin_result_2.text_output in received_output


    def test_server_scan_completed_with_http_tunneling(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        # When scanning through a proxy, we do not know the final server's IP address
        # This makes sure the console output properly handles that
        tunneling_settings = HttpConnectTunnelingSettings('ûnicôdé.com', 3128)
        server_info = MockServerConnectivityInfo(http_tunneling_settings=tunneling_settings)

        server_scan = CompletedServerScan(server_info, [])
        generator.server_scan_completed(server_scan)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly listed the online domain and that it was going through a proxy
        assert server_info.hostname in received_output.lower()
        assert str(server_info.port) in received_output.lower()
        assert 'proxy' in received_output.lower()
        assert tunneling_settings.hostname in received_output.lower()
        assert str(tunneling_settings.port) in received_output.lower()


    def test_scans_completed(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        scan_time = 1.3
        generator.scans_completed(scan_time)
        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output displayed the total scan time
        assert str(scan_time) in received_output
