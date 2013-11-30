#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:         PluginHSTS.py
# Purpose:      Checks if the server supports RFC 6797 HTTP Strict Transport
#               Security by checking if the server responds with the
#               Strict-Transport-Security field in the header.
#
#               Note: There is currently no support for hsts pinning.
#
#               This plugin is based on the plugin written by Tom Samstag
#               (tecknicaltom) and reworked, integrated and adapted to the
#               new sslyze plugin API by Joachim Strömbergson.
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
import httplib
from plugins import PluginBase


class PluginHSTS(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginHSTS", description=(''))
    interface.add_command(
        command="hsts",
        help="Checks support for HTTP Strict Transport Security "
             "(HSTS) by collecting any Strict-Transport-Security field present in "
             "the HTTP response sent back by the server.",
        dest=None)


    def process_task(self, target, command, args):

        if self._shared_settings['starttls']:
            raise Exception('Cannot use --hsts with --starttls.')
            
        output_format = '        {0:<25} {1}'

        hsts_supported = False
        hsts_timeout = ""
        (host, addr, port, sslVersion) = target
        connection = httplib.HTTPSConnection(host, port)
        try:
            connection.connect()
            connection.request("HEAD", "/", headers={"Connection": "close"})
            response = connection.getresponse()
            headers = response.getheaders()
            for (field, data) in headers:
                if field == 'strict-transport-security':
                    hsts_supported = True
                    hsts_timeout = data

        except httplib.HTTPException as ex:
            print "Error: %s" % ex

        finally:
            connection.close()

        # Text output
        cmd_title = 'HSTS'
        txt_result = [self.PLUGIN_TITLE_FORMAT(cmd_title)]
        if hsts_supported:
            txt_result.append(output_format.format("Supported:", hsts_timeout))
        else:
            txt_result.append(output_format.format("Not supported.", ""))

        # XML output
        xml_hsts_attr = {'hsts_header_found': str(hsts_supported)}
        if hsts_supported:
            xml_hsts_attr['hsts_header'] = hsts_timeout
        xml_hsts = Element('hsts', attrib = xml_hsts_attr)

        xml_result = Element(self.__class__.__name__, command = command,
                             title = cmd_title)
        xml_result.append(xml_hsts)

        return PluginBase.PluginResult(txt_result, xml_result)

