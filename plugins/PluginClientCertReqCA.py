#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginClientCertCA.py
# Purpose:      Retrieves a list of CA acceptable by server for
#               client certificates.
#
# Author:       kyprizel
#
# Copyright:    2015 SSLyze developers
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

from os.path import join, dirname, realpath, abspath
import inspect
import imp
from xml.etree.ElementTree import Element
import sys

from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl import X509_NAME_MISMATCH, X509_NAME_MATCHES_SAN, X509_NAME_MATCHES_CN
from nassl.SslClient import ClientCertificateRequested


class PluginClientCertReqCA(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginClientCertReqCA", description='')
    interface.add_command(
        command="clientreqca",
        help="")

    CMD_TITLE = "Client cerificate request CAs"

    def process_task(self, target, command, arg):
        """
        Connects to the target server and tries to get acceptable CAs for client cert
        """
        (_, _, _, ssl_version) = target
        ssl_conn = create_sslyze_connection(target, self._shared_settings, ssl_version)

        res = []
        try:  # Perform the SSL handshake
            ssl_conn.connect()

        except ClientCertificateRequested:  # The server asked for a client cert
            res = ssl_conn.get_client_CA_list()

        finally:
            ssl_conn.close()


        text_output = [self.PLUGIN_TITLE_FORMAT(self.CMD_TITLE)]
        if res:
            xml_output = Element(command, title=self.CMD_TITLE, isProvided="True")
            for ca in res:
                text_output.append(self.FIELD_FORMAT('', str(ca)))
                ca_xml = Element('ca')
                ca_xml.text = ca
                xml_output.append(ca_xml)
        else:
            xml_output = Element(command, title=self.CMD_TITLE, isProvided="False")

        return PluginBase.PluginResult(text_output, xml_output)
