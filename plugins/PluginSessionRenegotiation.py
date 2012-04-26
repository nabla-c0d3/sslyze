#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginSessionRenegotiation.py
# Purpose:      Tests the target server for insecure renegotiation.
#
# Author:       alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
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
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, SSL_CTX, \
    constants, errors


class PluginSessionRenegotiation(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginSessionRenegotiation",
        description="Tests the target server for insecure renegotiation.")
    available_commands.add_command(
        command="reneg",
        help=(
            "Tests the target server's support for client-initiated "
            'renegotiations and secure renegotiations.'),
        dest=None)


    def process_task(self, target, command, args):

        ctSSL_initialize()
        try:
            (can_reneg, is_secure) = self._test_renegotiation(target)
        finally:
            ctSSL_cleanup()
        
        # Text output
        reneg_txt = 'Honored' if can_reneg else 'Rejected'
        secure_txt = 'Supported' if is_secure else 'Not supported'
        
        txt_result = ['  * {0} : '.format('Session Renegotiation')]
        RENEG_FORMAT = '      {0:<35} {1}'
        txt_result.append(RENEG_FORMAT.format('Client-initiated Renegotiations:', reneg_txt))
        txt_result.append(RENEG_FORMAT.format('Secure Renegotiation: ', secure_txt))
        
        # XML output
        xml_reneg = Element('reneg', reneg='client initiated', supported = str(can_reneg))
        xml_secure = Element('reneg', reneg='secure', supported = str(is_secure))
        
        xml_result = Element(self.__class__.__name__, command=command)
        xml_result.extend([xml_reneg, xml_secure])
        
        return PluginBase.PluginResult(txt_result, xml_result)


    def _test_renegotiation(self, target):
        """
        Checks whether the server honors session renegotiation requests and 
        whether it supports secure renegotiation.
        """
        ssl_ctx = SSL_CTX.SSL_CTX()
        ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
        ssl_connect = \
            self._create_ssl_connection(target, ssl_ctx=ssl_ctx)
    
        try:
            ssl_connect.connect()
            is_secure = ssl_connect.ssl.get_secure_renegotiation_support()
    
            try: # Let's try to renegotiate
                ssl_connect.ssl.renegotiate()
                can_reneg = True
    
            # Errors caused by a server rejecting the renegotiation
            except errors.ctSSLUnexpectedEOF as e:
                can_reneg = False
            except socket.error as e:
                if 'connection was forcibly closed' in str(e.args):
                    can_reneg = False
                elif 'reset by peer' in str(e.args):
                    can_reneg = False
                else:
                    raise
            #except socket.timeout as e:
            #    result_reneg = 'Rejected (timeout)'
            except errors.SSLError as e:
                if 'handshake failure' in str(e.args):
                    can_reneg = False
                elif 'no renegotiation' in str(e.args):
                    can_reneg = False
                else:
                    raise
    
        finally:
            ssl_connect.close()
    
        return (can_reneg, is_secure)