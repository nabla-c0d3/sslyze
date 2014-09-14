#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginSessionRenegotiation.py
# Purpose:      Tests the target server for insecure renegotiation.
#
# Author:       alban
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

import socket
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl._nassl import OpenSSLError


class PluginSessionRenegotiation(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface("PluginSessionRenegotiation",  "")
    interface.add_command(
        command="reneg",
        help=(
            "Tests the server(s) for client-initiated "
            'renegotiation and secure renegotiation support.'))


    def process_task(self, target, command, args):

        (clientReneg, secureReneg) = self._test_renegotiation(target)

        # Text output
        clientTxt = 'VULNERABLE - Server honors client-initiated renegotiations' if clientReneg else 'OK - Rejected'
        secureTxt = 'OK - Supported' if secureReneg else 'VULNERABLE - Secure renegotiation not supported'
        cmdTitle = 'Session Renegotiation'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]

        txtOutput.append(self.FIELD_FORMAT('Client-initiated Renegotiations:', clientTxt))
        txtOutput.append(self.FIELD_FORMAT('Secure Renegotiation:', secureTxt))

        # XML output
        xmlReneg = Element('sessionRenegotiation',
                           attrib = {'canBeClientInitiated' : str(clientReneg),
                                     'isSecure' : str(secureReneg)})

        xmlOutput = Element(command, title=cmdTitle)
        xmlOutput.append(xmlReneg)

        return PluginBase.PluginResult(txtOutput, xmlOutput)


    def _test_renegotiation(self, target):
        """
        Checks whether the server honors session renegotiation requests and
        whether it supports secure renegotiation.
        """
        sslConn = create_sslyze_connection(target, self._shared_settings)

        try: # Perform the SSL handshake
            sslConn.connect()
            secureReneg = sslConn.get_secure_renegotiation_support()

            try: # Let's try to renegotiate
                sslConn.do_renegotiate()
                clientReneg = True

            # Errors caused by a server rejecting the renegotiation
            except socket.error as e:
                if 'connection was forcibly closed' in str(e.args):
                    clientReneg = False
                elif 'reset by peer' in str(e.args):
                    clientReneg = False
                else:
                    raise
            #except socket.timeout as e:
            #    result_reneg = 'Rejected (timeout)'
            except OpenSSLError as e:
                if 'handshake failure' in str(e.args):
                    clientReneg = False
                elif 'no renegotiation' in str(e.args):
                    clientReneg = False
                else:
                    raise

            # Should be last as socket errors are also IOError
            except IOError as e:
                if 'Nassl SSL handshake failed' in str(e.args):
                    clientReneg = False
                else:
                    raise

        finally:
            sslConn.close()

        return (clientReneg, secureReneg)
