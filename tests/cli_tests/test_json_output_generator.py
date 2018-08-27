import json
import unittest
from io import StringIO

from sslyze.cli import CompletedServerScan
from sslyze.cli.command_line_parser import ServerStringParsingError
from sslyze.cli.json_output import JsonOutputGenerator
from sslyze.server_connectivity_tester import ServerConnectivityError
from tests.cli_tests import MockServerConnectivityInfo, MockPluginScanResult, MockCommandLineValues, \
    MockPluginScanCommandOne, MockPluginScanCommandTwo, MockServerConnectivityTester


class JsonOutputGeneratorTestCase(unittest.TestCase):

    def test(self):
        """The final output only gets written at the end, when calling scans_completed(). Hence we need to call all the
        methods in the right order and validate the final output at the end.
        """
        output_file = StringIO()
        generator = JsonOutputGenerator(output_file)

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

        plugin_result_1 = MockPluginScanResult(server_info, MockPluginScanCommandOne(), 'Plugin ûnicôdé output', None)
        plugin_result_2 = MockPluginScanResult(server_info, MockPluginScanCommandTwo(), 'other plugin Output', None)
        server_scan = CompletedServerScan(server_info, [plugin_result_1, plugin_result_2])
        generator.server_scan_completed(server_scan)

        scan_time = 1.3
        generator.scans_completed(scan_time)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the output properly listed the parsing error with unicode escaped as \u sequences
        self.assertIn('www.badp\\u00e3rsing.com', received_output)
        self.assertIn('P\\u00e3rsing error', received_output)

        # Ensure the output properly listed the connectivity error with unicode escaped as \u sequences
        self.assertIn('unibade\\u00e9\\u00e8.com:443', received_output)
        self.assertIn('Some \\u00e9rr\\u00f4r', received_output)

        # Ensure the output properly listed the online domain
        self.assertIn(json.dumps(server_info.hostname, ensure_ascii=True), received_output)
        self.assertIn(str(server_info.port), received_output)
        self.assertIn(server_info.ip_address, received_output)

        # Ensure the output displayed the plugin's attributes as JSON
        self.assertIn(plugin_result_1.scan_command.get_cli_argument(), received_output)
        self.assertIn(plugin_result_2.scan_command.get_cli_argument(), received_output)
        self.assertIn('"text_output":', received_output)
        self.assertIn(json.dumps(plugin_result_1.text_output, ensure_ascii=True), received_output)
        self.assertIn(plugin_result_2.text_output, received_output)

        # Ensure the console output displayed the total scan time
        self.assertIn(str(scan_time), received_output)
