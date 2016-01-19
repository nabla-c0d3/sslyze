#!/usr/bin/env python2.7
#-------------------------------------------------------------------------------
# Name:         PluginCompression.py
# Purpose:      Tests the server for Zlib compression support.
#
# Author:       tritter, alban
#
# Copyright:    2012 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

from xml.etree.ElementTree import Element


from plugins import PluginBase

from nassl.SslClient import ClientCertificateRequested
from plugins.PluginBase import PluginResult


class PluginCompression(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCompression", description="")
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

    COMMAND_TITLE = 'Deflate Compression'

    def __init__(self, server_info, plugin_command, plugin_options, compression_name):
        super(CompressionResult, self).__init__(server_info, plugin_command, plugin_options)

        # Will be empty if no compression is supported by the server
        self.compression_name = compression_name

    def as_text(self):
        txt_result = [self.PLUGIN_TITLE_FORMAT(self.COMMAND_TITLE)]
        if self.compression_name:
            txt_result.append(self.FIELD_FORMAT('VULNERABLE - Server supports Deflate compression', ''))
        else:
            txt_result.append(self.FIELD_FORMAT('OK - Compression disabled', ''))
        return txt_result

    def as_xml(self):
        xml_result = Element(self.plugin_command, title=self.COMMAND_TITLE)
        if self.compression_name:
            xml_result.append(Element('compressionMethod', type="DEFLATE", isSupported="True"))
        else:
            xml_result.append(Element('compressionMethod', type="DEFLATE", isSupported="False"))
        return xml_result