#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginOpenSSLProtocolSupport.py
# Purpose:      Tests the server for supported SSL / TLS versions.
#
# Author:       bcyrill
#
# Copyright:    2014 SSLyze developers
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
from utils.SSLyzeSSLConnection import create_sslyze_connection, SSLHandshakeRejected
from nassl import SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2


class PluginOpenSSLProtocolSupport(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginOpenSSLProtocolSupport", description="")
    interface.add_command(
        command="protocols",
        help="Checks the support for the available SSL and TLS protocols.",
        dest=None)


    def process_task(self, target, command, args):
        
        OUT_FORMAT = '      {0:<35}{1}'.format
        
        sslVersionDict = [('SSLv2', SSLV2), 
                        ('SSLv3', SSLV3),
                        ('TLSv1.0', TLSV1),
                        ('TLSv1.1', TLSV1_1),
                        ('TLSv1.2', TLSV1_2)]
        
        cmdTitle = 'Protocol Version'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]
        xmlOutput = Element(command, title=cmdTitle)
        
        for (sslVersionName, sslVersion) in sslVersionDict:
            xmlNode = None
            
            sslConn = create_sslyze_connection(target, self._shared_settings, sslVersion)
            sslConn.set_cipher_list('ALL:COMPLEMENTOFALL')
            
            try: # Perform the SSL handshake
                sslConn.connect()
                isSupported = 'Supported'
                xmlNode = Element(sslVersionName)

            except SSLHandshakeRejected as e:
                isSupported = 'Not Supported - ' + str(e)

            except:
                raise
            
            finally:
                sslConn.close()
                txtOutput.append(OUT_FORMAT(sslVersionName, isSupported))
                if xmlNode is not None:
                    xmlOutput.append(xmlNode)
        
        return PluginBase.PluginResult(txtOutput, xmlOutput)

