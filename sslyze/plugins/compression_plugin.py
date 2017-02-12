# -*- coding: utf-8 -*-

from xml.etree.ElementTree import Element
from nassl.ssl_client import ClientCertificateRequested
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from typing import Text


class CompressionScanCommand(PluginScanCommand):
    """Test the server(s) for Zlib compression support.
    """

    @classmethod
    def get_cli_argument(cls):
        return u'compression'


class CompressionPlugin(plugin_base.Plugin):
    """Test the server(s) for Zlib compression support.
    """

    @classmethod
    def get_available_commands(cls):
        return [CompressionScanCommand]

    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, CompressionScanCommand) -> CompressionScanResult
        ssl_connection = server_info.get_preconfigured_ssl_connection()

        # Make sure OpenSSL was built with support for compression to avoid false negatives
        if u'zlib compression' not in ssl_connection.get_available_compression_methods():
            raise RuntimeError(u'OpenSSL was not built with support for zlib / compression. '
                               u'Did you build nassl yourself ?')

        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            compression_name = ssl_connection.get_current_compression_method()
        except ClientCertificateRequested:
            # The server asked for a client cert
            compression_name = ssl_connection.get_current_compression_method()
        finally:
            ssl_connection.close()

        return CompressionScanResult(server_info, scan_command, compression_name)


class CompressionScanResult(PluginScanResult):
    """The result of running a CompressionScanCommand on a specific server.

    Attributes:
        compression_name (Optional[Text]): The name of the compression algorithm supported by the server; None if
            compression is not supported by the server.
    """

    COMMAND_TITLE = u'Deflate Compression'

    def __init__(self, server_info, scan_command, compression_name):
        # type: (ServerConnectivityInfo, CompressionScanCommand, Text) -> None
        super(CompressionScanResult, self).__init__(server_info, scan_command)
        self.compression_name = compression_name

    def as_text(self):
        txt_result = [self._format_title(self.COMMAND_TITLE)]
        if self.compression_name:
            txt_result.append(self._format_field(u'', u'VULNERABLE - Server supports Deflate compression'))
        else:
            txt_result.append(self._format_field(u'', u'OK - Compression disabled'))
        return txt_result

    def as_xml(self):
        xml_result = Element(self.scan_command.get_cli_argument(), title=self.COMMAND_TITLE)
        if self.compression_name:
            xml_result.append(Element('compressionMethod', type="DEFLATE", isSupported="True"))
        else:
            xml_result.append(Element('compressionMethod', type="DEFLATE", isSupported="False"))
        return xml_result
