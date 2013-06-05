#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:         PluginHSTS.py
# Purpose:      Checks if the server supports RFC 6797 HTTP Strict Transport
#               Security by checking if the server responds with the
#               Strict-Transport-Security field in the header.
#
#               This plugin was written by Tom Samstag (tecknicaltom) and
#               integrated, adapted by Joachim Strömbergson
#
# Author:       tecknicaltom, joachims
#
# Copyright:    2013 SSLyze developers
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
import socket

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup

class PluginHSTS(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginHSTS", description=(''))
    interface.add_command(
        command="hsts",
        help="Verifies the support of a server for HTTP Strict Transport Security "
             "(HSTS) by collecting any Strict-Transport-Security field present in "
             "the response from the server.",
        dest=None)

    def process_task(self, target, command, args):

        output_format = '        {0:<25} {1}'

        ctSSL_initialize()
        ssl_connect = self._create_ssl_connection(target)

        header = None

        #try: # Perform the SSL handshake
        ssl_connect.connect()
        ssl_connect.request("HEAD", "/", headers={"Connection": "close"})
        http_response = ssl_connect.getresponse()
        header = http_response.getheader('Strict-Transport-Security', None)

        ctSSL_cleanup()

        # Text output
        cmd_title = 'HSTS'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        txt_result.append(output_format.format("Strict-Transport-Security header:", header))

        # XML output
        xml_hsts_attr = {'header_found': str(header != None)}
        if header:
            xml_hsts_attr['header'] = header
        xml_hsts = Element('hsts', attrib = xml_hsts_attr)
        
        xml_result = Element(self.__class__.__name__, command = command,
                             title = cmd_title)
        xml_result.append(xml_hsts)

        return PluginBase.PluginResult(txt_result, xml_result)

