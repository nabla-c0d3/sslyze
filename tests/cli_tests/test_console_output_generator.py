# coding=utf-8
import unittest
from StringIO import StringIO

from sslyze.cli import FailedServerScan, CompletedServerScan
from sslyze.cli.console_output import ConsoleOutputGenerator
from sslyze.server_connectivity import ServerConnectivityError, ClientAuthenticationServerConfigurationEnum
from tests.cli_tests import MockServerConnectivityInfo, MockPluginResult


class ConsoleOutputGeneratorTestCase(unittest.TestCase):

    def test_command_line_parsed(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        class FakePlugin1(object):
            pass

        class FakePlugin2(object):
            pass

        generator.command_line_parsed([FakePlugin1, FakePlugin2], None)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly listed the available plugins
        self.assertIn('FakePlugin1', received_output)
        self.assertIn('FakePlugin2', received_output)


    def test_server_connectivity_test_failed(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        failed_scan = FailedServerScan(server_string=u'unicödeéè.com',
                                       connection_exception=ServerConnectivityError(error_msg=u'Some érrôr'))
        generator.server_connectivity_test_failed(failed_scan)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly listed the connectivity error with unicode
        self.assertIn(u'unicödeéè.com', received_output)
        self.assertIn(u'Some érrôr', received_output)
        self.assertIn('discarding corresponding tasks', received_output)


    def test_server_connectivity_test_succeeded(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        server_info = MockServerConnectivityInfo()
        generator.server_connectivity_test_succeeded(server_info)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly listed the online domain
        self.assertIn(server_info.hostname, received_output)
        self.assertIn(str(server_info.port), received_output)
        self.assertIn(server_info.ip_address, received_output)


        # Test when client authentication is required
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        server_info = MockServerConnectivityInfo(ClientAuthenticationServerConfigurationEnum.REQUIRED)
        generator.server_connectivity_test_succeeded(server_info)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly warned about client authentication
        self.assertIn('Server REQUIRED client authentication', received_output)


        # Test when client authentication is optional
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        server_info = MockServerConnectivityInfo(ClientAuthenticationServerConfigurationEnum.OPTIONAL)
        generator.server_connectivity_test_succeeded(server_info)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output properly warned about client authentication
        self.assertIn('Server requested optional client authentication', received_output)


    def test_scans_started(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        generator.scans_started()

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output displayed something
        self.assertTrue(received_output)


    def test_server_scan_completed(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        server_info = MockServerConnectivityInfo()
        plugin_result_1 = MockPluginResult(u'Plugin ûnicôdé output')
        plugin_result_2 = MockPluginResult('other plugin Output')
        server_scan = CompletedServerScan(server_info, [plugin_result_1, plugin_result_2])
        generator.server_scan_completed(server_scan)

        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output displayed the server's info
        self.assertIn(server_info.hostname, received_output.lower())
        self.assertIn(str(server_info.port), received_output)
        self.assertIn(server_info.ip_address, received_output.lower())

        # Ensure the console output displayed the plugin text outputs
        self.assertIn(plugin_result_1.text_output, received_output)
        self.assertIn(plugin_result_2.text_output, received_output)


    def test_scans_completed(self):
        output_file = StringIO()
        generator = ConsoleOutputGenerator(output_file)

        scan_time = 1.3
        generator.scans_completed(scan_time)
        received_output = output_file.getvalue()
        output_file.close()

        # Ensure the console output displayed the total scan time
        self.assertIn(str(scan_time), received_output)
