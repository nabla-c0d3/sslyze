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

from utils.SSLyzeSSLConnection import create_sslyze_connection, ClientAuthenticationError


class PluginCompression(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCompression", description="")
    interface.add_command(
        command="compression",
        help="Tests the server for Zlib compression support.",
        dest=None)


    def process_task(self, target, command, args):
        
        OUT_FORMAT = '        {0:<25} {1}'.format

        sslConn = create_sslyze_connection(self._shared_settings)

        try: # Perform the SSL handshake
            sslConn.connect((target[0], target[2]))
            compName = sslConn.get_current_compression_name()
        except ClientAuthenticationError: # The server asked for a client cert
            compName = sslConn.get_current_compression_name()
        finally:
            sslConn.close()
      
        # Text output
        if compName:
            compTxt = 'Enabled ' +  compName
            compXml = {'isSupported':'True','type':compName.strip('()')}
        else:
            compTxt = 'Disabled'
            compXml = {'isSupported':'False'}
            
        cmdTitle = 'Compression'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]
        txtOutput.append(OUT_FORMAT("Compression Support:", compTxt))

        # XML output
        xmlNode = Element('compression', compXml)
        xmlOutput = Element(command, title = cmdTitle)
        xmlOutput.append(xmlNode)

        return PluginBase.PluginResult(txtOutput, xmlOutput)

