# coding=utf-8
import json
import unittest
from StringIO import StringIO

from sslyze.cli import FailedServerScan, CompletedServerScan
from sslyze.cli.json_output import JsonOutputGenerator
from sslyze.server_connectivity import ServerConnectivityError
from tests.cli_tests import MockServerConnectivityInfo, MockPluginResult, MockCommandLineValues


class JsonOutputGeneratorTestCase(unittest.TestCase):

    def test(self):
        """The final output only gets written at the end, when calling scans_completed(). Hence we need to call all the
        methods in the right order and validate the final output at the end.
        """
        output_file = StringIO()
        generator = JsonOutputGenerator(output_file)

        generator.command_line_parsed(None, MockCommandLineValues())

        failed_scan = FailedServerScan(server_string=u'unibadeéè.com',
                                       connection_exception=ServerConnectivityError(error_msg=u'Some érrôr'))
        generator.server_connectivity_test_failed(failed_scan)

        server_info = MockServerConnectivityInfo()
        generator.server_connectivity_test_succeeded(server_info)

        generator.scans_started()

        # noinspection PyTypeChecker
        plugin_result_1 = MockPluginResult(u'plugin1', u'Plugin ûnicôdé output', None)
        # noinspection PyTypeChecker
        plugin_result_2 = MockPluginResult(u'plugin2', u'other plugin Output', None)
        # noinspection PyTypeChecker
        server_scan = CompletedServerScan(server_info, [plugin_result_1, plugin_result_2])
        generator.server_scan_completed(server_scan)

        scan_time = 1.3
        generator.scans_completed(scan_time)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the output properly listed the connectivity error with unicode escaped as \u sequences
        self.assertIn(json.dumps(u'unibadeéè.com', ensure_ascii=True), received_output)
        self.assertIn(json.dumps(u'Some érrôr', ensure_ascii=True), received_output)

        # Ensure the output properly listed the online domain
        self.assertIn(json.dumps(server_info.hostname, ensure_ascii=True), received_output)
        self.assertIn(str(server_info.port), received_output)
        self.assertIn(server_info.ip_address, received_output)

        # Ensure the output displayed the plugin's attributes as JSON
        self.assertIn(plugin_result_1.plugin_command, received_output)
        self.assertIn(plugin_result_2.plugin_command, received_output)
        self.assertIn('"text_output":', received_output)
        self.assertIn(json.dumps(plugin_result_1.text_output, ensure_ascii=True), received_output)
        self.assertIn(plugin_result_2.text_output, received_output)

        # Ensure the console output displayed the total scan time
        self.assertIn(str(scan_time), received_output)
        self.assertIn('"network_timeout": "{}"'.format(MockCommandLineValues().timeout), received_output)
        self.assertIn('"network_max_retries": "{}"'.format(MockCommandLineValues().nb_retries), received_output)
