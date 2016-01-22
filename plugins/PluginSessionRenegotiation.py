#!/usr/bin/env python2.7
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
from nassl._nassl import OpenSSLError

from plugins.PluginBase import PluginResult


class PluginSessionRenegotiation(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface("PluginSessionRenegotiation",  "")
    interface.add_command(
        command="reneg",
        help='Tests the server(s) for client-initiated renegotiation and secure renegotiation support.'
    )


    def process_task(self, server_info, command, options_dict=None):
        # Check for client-initiated renegotiation
        accepts_client_renegotiation = self._test_client_renegotiation(server_info)

        # Check for secure renegotiation
        supports_secure_renegotiation = self._test_secure_renegotiation(server_info)

        return SessionRenegotiationResult(server_info, command, options_dict, accepts_client_renegotiation,
                                          supports_secure_renegotiation)


    def _test_secure_renegotiation(self, server_info):
        """Checks whether the server supports secure renegotiation.
        """
        ssl_connection = server_info.get_preconfigured_ssl_connection()

        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            supports_secure_renegotiation = ssl_connection.get_secure_renegotiation_support()

        finally:
            ssl_connection.close()

        return supports_secure_renegotiation


    def _test_client_renegotiation(self, server_info):
        """Checks whether the server honors session renegotiation requests.
        """
        ssl_connection = server_info.get_preconfigured_ssl_connection()

        try:
            # Perform the SSL handshake
            ssl_connection.connect()

            try:
                # Let's try to renegotiate
                ssl_connection.do_renegotiate()
                accepts_client_renegotiation = True

            # Errors caused by a server rejecting the renegotiation
            except socket.timeout as e:
                # This is how Netty rejects a renegotiation - https://github.com/nabla-c0d3/sslyze/issues/114
                    accepts_client_renegotiation = False
            except socket.error as e:
                if 'connection was forcibly closed' in str(e.args):
                    accepts_client_renegotiation = False
                elif 'reset by peer' in str(e.args):
                    accepts_client_renegotiation = False
                else:
                    raise
            except OpenSSLError as e:
                if 'handshake failure' in str(e.args):
                    accepts_client_renegotiation = False
                elif 'no renegotiation' in str(e.args):
                    accepts_client_renegotiation = False
                elif 'tlsv1 unrecognized name' in str(e.args):
                    # Yahoo's very own way of rejecting a renegotiation
                    accepts_client_renegotiation = False
                else:
                    raise

            # Should be last as socket errors are also IOError
            except IOError as e:
                if 'Nassl SSL handshake failed' in str(e.args):
                    accepts_client_renegotiation = False
                else:
                    raise

        finally:
            ssl_connection.close()

        return accepts_client_renegotiation


class SessionRenegotiationResult(PluginResult):

    COMMAND_TITLE = 'Session Renegotiation'

    def __init__(self, server_info, plugin_command, plugin_options, accepts_client_renegotiation,
                 supports_secure_renegotiation):
        super(SessionRenegotiationResult, self).__init__(server_info, plugin_command, plugin_options)
        self.accepts_client_renegotiation = accepts_client_renegotiation
        self.supports_secure_renegotiation = supports_secure_renegotiation


    def as_text(self):
        result_txt = [self.PLUGIN_TITLE_FORMAT(self.COMMAND_TITLE)]

        # Client-initiated reneg
        client_reneg_txt = 'VULNERABLE - Server honors client-initiated renegotiations' \
            if self.accepts_client_renegotiation \
            else 'OK - Rejected'
        result_txt.append(self.FIELD_FORMAT('Client-initiated Renegotiation:', client_reneg_txt))

        # Secure reneg
        secure_txt = 'OK - Supported' \
            if self.supports_secure_renegotiation \
            else 'VULNERABLE - Secure renegotiation not supported'
        result_txt.append(self.FIELD_FORMAT('Secure Renegotiation:', secure_txt))

        return result_txt


    def as_xml(self):
        result_xml = Element(self.plugin_command, title=self.COMMAND_TITLE)
        result_xml.append(Element('sessionRenegotiation',
                                  attrib={'canBeClientInitiated': str(self.accepts_client_renegotiation),
                                          'isSecure': str(self.supports_secure_renegotiation)}))
        return result_xml
