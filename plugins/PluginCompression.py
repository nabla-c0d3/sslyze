#!/usr/bin/env python
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
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, SSL_CTX
from utils.SSLyzeSSLConnection import SSLyzeSSLConnection



class PluginCompression(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCompression", description="")
    interface.add_command(
        command="compression",
        help="Tests the server for Zlib compression support.",
        dest=None)

    def process_task(self, target, command, args):
        output_format = '        {0:<25} {1}'

        ctSSL_initialize(zlib=True)

        ssl_ctx = SSL_CTX.SSL_CTX('tlsv1') # sslv23 hello will fail for specific servers such as post.craigslist.org
        ssl_connect = SSLyzeSSLConnection(self._shared_settings, target,ssl_ctx,
                                          hello_workaround=True)

        try: # Perform the SSL handshake
            ssl_connect.connect()
            compression_status = ssl_connect._ssl.get_current_compression()
        finally:
            ssl_connect.close()
            
        ctSSL_cleanup()

        # Text output
        if compression_status:
            comp_txt = 'Enabled ' +  compression_status
            comp_xml = {'isSupported':'True','type':compression_status.strip('()')}
        else:
            comp_txt = 'Disabled'
            comp_xml = {'isSupported':'False'}
            
        cmd_title = 'Compression'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        txt_result.append(output_format.format("Compression Support:", comp_txt))

        # XML output
        xml_el = Element('compression', comp_xml)
        xml_result = Element(command, title = cmd_title)
        xml_result.append(xml_el)

        return PluginBase.PluginResult(txt_result, xml_result)

