from io import StringIO
from xml.etree.ElementTree import Element

from sslyze.cli import CompletedServerScan
from sslyze.cli.command_line_parser import ServerStringParsingError
from sslyze.cli.xml_output import XmlOutputGenerator
from sslyze.server_connectivity_tester import ServerConnectivityError
from sslyze.ssl_settings import HttpConnectTunnelingSettings
from tests.cli_tests import MockServerConnectivityInfo, MockPluginScanResult, MockCommandLineValues, \
    MockPluginScanCommandOne, MockPluginScanCommandTwo, MockServerConnectivityTester


class TestXmlOutputGenerator:

    def test(self):
        """The final output only gets written at the end, when calling scans_completed(). Hence we need to call all the
        methods in the right order and validate the final output at the end.
        """
        output_file = StringIO()
        generator = XmlOutputGenerator(output_file)

        failed_parsing = ServerStringParsingError(
            supplied_server_string='www.badpãrsing.com',
            error_message='Pãrsing error'
        )
        generator.command_line_parsed(set(), MockCommandLineValues(), [failed_parsing])

        failed_scan = ServerConnectivityError(
            server_info=MockServerConnectivityTester(hostname='unibadeéè.com'),
            error_message='Some érrôr'
        )
        generator.server_connectivity_test_failed(failed_scan)

        server_info = MockServerConnectivityInfo()
        generator.server_connectivity_test_succeeded(server_info)

        generator.scans_started()

        plugin_xml_out_1 = Element('plugin1', attrib={'test1': 'value1'})
        plugin_xml_out_1.text = 'Plugin ûnicôdé output'
        plugin_result_1 = MockPluginScanResult(server_info, MockPluginScanCommandOne(), '', plugin_xml_out_1)
        plugin_xml_out_2 = Element('plugin2', attrib={'test2': 'value2'})
        plugin_xml_out_2.text = 'other plugin Output'
        plugin_result_2 = MockPluginScanResult(server_info, MockPluginScanCommandTwo(), '', plugin_xml_out_2)

        server_scan = CompletedServerScan(server_info, [plugin_result_1, plugin_result_2])
        generator.server_scan_completed(server_scan)

        scan_time = 1.3
        generator.scans_completed(scan_time)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the output properly listed the parsing error
        assert 'www.badpãrsing.com' in received_output
        assert 'Pãrsing error' in received_output

        # Ensure the output properly listed the connectivity error
        assert 'unibadeéè.com' in received_output
        assert 'Some érrôr' in received_output

        # Ensure the output properly listed the online domain
        assert server_info.hostname in received_output
        assert str(server_info.port) in received_output
        assert server_info.ip_address in received_output

        # Ensure the output displayed the plugin's XML output
        assert plugin_result_1.scan_command.get_cli_argument() in received_output
        assert plugin_result_2.scan_command.get_cli_argument() in received_output
        assert plugin_result_1.as_xml().text in received_output
        assert plugin_result_2.as_xml().text in received_output

        # Ensure the console output displayed the total scan time
        assert 'totalScanTime="{}"'.format(scan_time) in received_output

    def test_with_http_tunneling(self):
        output_file = StringIO()
        generator = XmlOutputGenerator(output_file)

        # When scanning through a proxy, we do not know the final server's IP address
        # This makes sure the XML output properly handles that
        tunneling_settings = HttpConnectTunnelingSettings('prôxyé.com', 3128)
        server_info = MockServerConnectivityInfo(http_tunneling_settings=tunneling_settings)

        # noinspection PyTypeChecker
        server_scan = CompletedServerScan(server_info, [])
        generator.server_scan_completed(server_scan)
        generator.scans_completed(1.3)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the output displayed the tunneling settings
        assert 'httpsTunnelHostname="{}"'.format(tunneling_settings.hostname) in received_output
        assert 'httpsTunnelPort="{}"'.format(tunneling_settings.port) in received_output
