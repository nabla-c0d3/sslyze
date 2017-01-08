# coding=utf-8
import unittest
from StringIO import StringIO
from xml.etree.ElementTree import Element

from sslyze.cli import FailedServerScan, CompletedServerScan
from sslyze.cli.xml_output import XmlOutputGenerator
from sslyze.server_connectivity import ServerConnectivityError
from sslyze.ssl_settings import HttpConnectTunnelingSettings
from tests.cli_tests import MockServerConnectivityInfo, MockPluginResult, MockCommandLineValues


class XmlOutputGeneratorTestCase(unittest.TestCase):

    def test(self):
        """The final output only gets written at the end, when calling scans_completed(). Hence we need to call all the
        methods in the right order and validate the final output at the end.
        """
        output_file = StringIO()
        generator = XmlOutputGenerator(output_file)

        generator.command_line_parsed(None, MockCommandLineValues())

        failed_scan = FailedServerScan(server_string=u'unibadeéè.com',
                                       connection_exception=ServerConnectivityError(error_msg=u'Some érrôr'))
        generator.server_connectivity_test_failed(failed_scan)

        server_info = MockServerConnectivityInfo()
        generator.server_connectivity_test_succeeded(server_info)

        generator.scans_started()

        plugin_xml_out_1 = Element(u'plugin1', attrib={'test1': 'value1'})
        plugin_xml_out_1.text = u'Plugin ûnicôdé output'
        plugin_result_1 = MockPluginResult('plugin1', u'', plugin_xml_out_1)
        plugin_xml_out_2 = Element(u'plugin2', attrib={'test2': 'value2'})
        plugin_xml_out_2.text = u'other plugin Output'
        plugin_result_2 = MockPluginResult('plugin2', u'', plugin_xml_out_2)

        # noinspection PyTypeChecker
        server_scan = CompletedServerScan(server_info, [plugin_result_1, plugin_result_2])
        generator.server_scan_completed(server_scan)

        scan_time = 1.3
        generator.scans_completed(scan_time)

        received_output = unicode(output_file.getvalue(), 'utf-8')
        output_file.close()

        # Ensure the output properly listed the connectivity error with unicode escaped as \u sequences
        self.assertIn(u'unibadeéè.com', received_output)
        self.assertIn(u'Some érrôr', received_output)

        # Ensure the output properly listed the online domain
        self.assertIn(server_info.hostname, received_output)
        self.assertIn(str(server_info.port), received_output)
        self.assertIn(server_info.ip_address, received_output)

        # Ensure the output displayed the plugin's XML output
        self.assertIn(plugin_result_1.plugin_command, received_output)
        self.assertIn(plugin_result_2.plugin_command, received_output)
        self.assertIn(plugin_result_1.as_xml().text, received_output)
        self.assertIn(plugin_result_2.as_xml().text, received_output)

        # Ensure the console output displayed the total scan time
        self.assertIn('totalScanTime="{}"'.format(scan_time), received_output)
        self.assertIn('networkTimeout="{}"'.format(MockCommandLineValues().timeout), received_output)
        self.assertIn('networkMaxRetries="{}"'.format(MockCommandLineValues().nb_retries), received_output)


    def test_with_http_tunneling(self):
        output_file = StringIO()
        generator = XmlOutputGenerator(output_file)

        # When scanning through a proxy, we do not know the final server's IP address
        # This makes sure the XML output properly handles that
        tunneling_settings = HttpConnectTunnelingSettings(u'prôxyé.com', 3128)
        server_info = MockServerConnectivityInfo(http_tunneling_settings=tunneling_settings)

        # noinspection PyTypeChecker
        server_scan = CompletedServerScan(server_info, [])
        generator.server_scan_completed(server_scan)
        generator.scans_completed(1.3)

        received_output = unicode(output_file.getvalue(), 'utf-8')
        output_file.close()

        # Ensure the output displayed the tunneling settings
        self.assertIn(u'httpsTunnelHostname="{}"'.format(tunneling_settings.hostname), received_output)
        self.assertIn('httpsTunnelPort="{}"'.format(tunneling_settings.port), received_output)
