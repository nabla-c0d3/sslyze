import re
from typing import Dict, TextIO, Any, Type, Set, List
from xml.dom import minidom

from sslyze import PROJECT_URL, __version__
from sslyze.cli import CompletedServerScan
from sslyze.cli.command_line_parser import ServerStringParsingError
from sslyze.cli.output_generator import OutputGenerator
from sslyze.plugins.plugin_base import Plugin
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.server_connectivity_tester import ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from xml.etree.ElementTree import Element, tostring


class XmlOutputGenerator(OutputGenerator):

    TLS_PROTOCOL_XML_TEXT: Dict[TlsWrappedProtocolEnum, str] = {
        TlsWrappedProtocolEnum.PLAIN_TLS: 'plainTls',
        TlsWrappedProtocolEnum.HTTPS: 'https',
        TlsWrappedProtocolEnum.STARTTLS_SMTP: 'startTlsSmtp',
        TlsWrappedProtocolEnum.STARTTLS_XMPP: 'startTlsXmpp',
        TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER: 'startTlsXmppServer',
        TlsWrappedProtocolEnum.STARTTLS_POP3: 'startTlsPop3',
        TlsWrappedProtocolEnum.STARTTLS_IMAP: 'startTlsImap',
        TlsWrappedProtocolEnum.STARTTLS_FTP: 'startTlsFtp',
        TlsWrappedProtocolEnum.STARTTLS_LDAP: 'startTlsLdap',
        TlsWrappedProtocolEnum.STARTTLS_RDP: 'startTlsRdp',
        TlsWrappedProtocolEnum.STARTTLS_POSTGRES: 'startTlsPostGres',
    }

    def __init__(self, file_to: TextIO) -> None:
        super().__init__(file_to)
        self._xml_root_node = Element('document', title="SSLyze Scan Results", SSLyzeVersion=__version__,
                                      SSLyzeWeb=PROJECT_URL)
        # The root node has two children nodes
        self._xml_results_node = Element('results')
        self._xml_failed_scans_node = Element('invalidTargets')

        self._xml_root_node.append(self._xml_results_node)
        self._xml_root_node.append(self._xml_failed_scans_node)

    def command_line_parsed(
            self,
            available_plugins: Set[Type[Plugin]],
            args_command_list: Any,
            malformed_servers: List[ServerStringParsingError]
    ) -> None:
        for bad_server_str in malformed_servers:
            failed_scan_node = Element('invalidTarget', error=bad_server_str.error_message)
            failed_scan_node.text = bad_server_str.server_string
            self._xml_failed_scans_node.append(failed_scan_node)

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        pass

    def server_connectivity_test_failed(self, connectivity_error: ServerConnectivityError) -> None:
        failed_scan_node = Element('invalidTarget', error=connectivity_error.error_message)
        server_info = connectivity_error.server_info
        failed_scan_node.text = '{}:{}'.format(server_info.hostname, server_info.port)
        self._xml_failed_scans_node.append(failed_scan_node)

    def scans_started(self) -> None:
        pass

    def server_scan_completed(self, server_scan_result: CompletedServerScan) -> None:
        # Add server info
        server_info = server_scan_result.server_info
        target_attrib = {'host': server_info.hostname,
                         'port': str(server_info.port),
                         'tlsWrappedProtocol': self.TLS_PROTOCOL_XML_TEXT[server_info.tls_wrapped_protocol]}

        # Add proxy settings
        if server_info.http_tunneling_settings:
            target_attrib['httpsTunnelHostname'] = server_info.http_tunneling_settings.hostname
            target_attrib['httpsTunnelPort'] = str(server_info.http_tunneling_settings.port)
        elif server_info.ip_address:
            # We only know the IP if we're not scanning through a proxy
            target_attrib['ip'] = server_info.ip_address
        else:
            raise RuntimeError('Should never happen')

        server_scan_node = Element('target', attrib=target_attrib)
        server_scan_result.plugin_result_list.sort(key=lambda result: result.scan_command.get_cli_argument())

        # Add each plugins's XML output
        for plugin_result in server_scan_result.plugin_result_list:
            server_scan_node.append(plugin_result.as_xml())

        self._xml_results_node.append(server_scan_node)

    def scans_completed(self, total_scan_time: float) -> None:
        self._xml_results_node.attrib['totalScanTime'] = str(total_scan_time)

        # Generate the final output
        # Remove characters that are illegal for XML
        # https://lsimons.wordpress.com/2011/03/17/stripping-illegal-characters-out-of-xml-in-python/
        xml_final_string = tostring(self._xml_root_node, encoding='utf-8').decode('utf-8')
        illegal_xml_chars_re = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1F\uD800-\uDFFF\uFFFE\uFFFF]')
        xml_sanitized_final_string = illegal_xml_chars_re.sub('', xml_final_string).encode('utf-8')

        # Hack: Prettify the XML file so it's (somewhat) diff-able
        xml_final_pretty = minidom.parseString(xml_sanitized_final_string).toprettyxml(indent="  ", encoding="utf-8")
        self._file_to.write(xml_final_pretty.decode('utf-8'))
