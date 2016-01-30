# -*- coding: utf-8 -*-
"""Plugin to test the server for Zlib compression support.
"""

from xml.etree.ElementTree import Element
from nassl.ssl_client import ClientCertificateRequested
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginResult


class CompressionPlugin(plugin_base.PluginBase):

    interface = plugin_base.PluginInterface(title="CompressionPlugin", description="")
    interface.add_command(
        command="compression",
        help="Tests the server(s) for Zlib compression support.")


    def process_task(self, server_info, command, options_dict=None):
        ssl_connection = server_info.get_preconfigured_ssl_connection()

        # Make sure OpenSSL was built with support for compression to avoid false negatives
        if 'zlib compression' not in ssl_connection.get_available_compression_methods():
            raise RuntimeError('OpenSSL was not built with support for zlib / compression. '
                               'Did you build nassl yourself ?')

        try: # Perform the SSL handshake
            ssl_connection.connect()
            compression_name = ssl_connection.get_current_compression_method()
        except ClientCertificateRequested:
            # The server asked for a client cert
            compression_name = ssl_connection.get_current_compression_method()
        finally:
            ssl_connection.close()

        return CompressionResult(server_info, command, options_dict, compression_name)


class CompressionResult(PluginResult):
    """The result of running --compression on a specific server.

    Attributes:
        compression_name (str): The name of the compression algorithm supported by the server; empty if compression is
            not supported by the server.
    """

    COMMAND_TITLE = 'Deflate Compression'

    def __init__(self, server_info, plugin_command, plugin_options, compression_name):
        super(CompressionResult, self).__init__(server_info, plugin_command, plugin_options)
        self.compression_name = compression_name

    def as_text(self):
        txt_result = [self.PLUGIN_TITLE_FORMAT(self.COMMAND_TITLE)]
        if self.compression_name:
            txt_result.append(self.FIELD_FORMAT('', 'VULNERABLE - Server supports Deflate compression'))
        else:
            txt_result.append(self.FIELD_FORMAT('', 'OK - Compression disabled'))
        return txt_result

    def as_xml(self):
        xml_result = Element(self.plugin_command, title=self.COMMAND_TITLE)
        if self.compression_name:
            xml_result.append(Element('compressionMethod', type="DEFLATE", isSupported="True"))
        else:
            xml_result.append(Element('compressionMethod', type="DEFLATE", isSupported="False"))
        return xml_result