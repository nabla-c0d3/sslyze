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

import socket

from xml.etree.ElementTree import Element
from utils.HTTPResponseParser import parse_http_response
from utils.SSLyzeSSLConnection import create_sslyze_connection
from plugins import PluginBase
from urlparse import urlparse
import Cookie


class PluginHTTPRedirect(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginHTTPRedirect", description=(''))
    interface.add_command(
        command="httpredirect",
        help="Checks if host installed HTTP to HTTPS redirect.",
        dest=None)


    def process_task(self, target, command, args):
        if self._shared_settings['starttls']:
            raise Exception('Cannot use --httpredirect with --starttls.')

        self._target = target
        self._ip = target[1]
        self._timeout = self._shared_settings['timeout']
        (status, redirect_header) = self._get_redirect_header()
        redirect_installed = False
        if redirect_header and status > 0:
            redirect_installed = True

        # Text output
        cmd_title = 'HTTP to HTTPS Redirect'
        txt_result = [self.PLUGIN_TITLE_FORMAT(cmd_title)]
        if redirect_installed:
            txt_result.append(self.FIELD_FORMAT("OK - HTTP to HTTPS header received:", redirect_header))
        else:
            txt_result.append(self.FIELD_FORMAT("NOT INSTALLED - Server did not send an HTTP to HTTPS redirect header.", ""))
            if status < 0:
                txt_result.append(self.FIELD_FORMAT(redirect_header, ""))

        # XML output
        xml_redirect_attr = {'isInstalled': str(redirect_installed)}
        if redirect_installed:
            xml_redirect_attr['location'] = redirect_header
            xml_redirect_attr['status'] = str(status)

        if status < 0:
            xml_redirect_attr['error'] = redirect_header

        xml_result = Element('HTTPredirect', title=cmd_title, attrib=xml_redirect_attr)

        return PluginBase.PluginResult(txt_result, xml_result)


    def _get_redirect_header(self):

        redirectHeader = None
        httpGetFormat = 'GET {0} HTTP/1.0\r\nHost: {1}\r\n{2}Connection: close\r\n\r\n'.format
        httpPath = '/'
        httpAppend = ''
        
        try:
            conn = socket.create_connection((self._ip, 80), self._timeout)
        except:
            return (-1, 'Error connecting to %s:80' % self._ip)
        conn.sendall(httpGetFormat(httpPath, self._target[0], httpAppend))
        httpResp = parse_http_response(conn)
        conn.close()
            
        if httpResp.version == 9 :
            # HTTP 0.9 => Probably not an HTTP response
            return (-1, 'Server did not return an HTTP response')

        # Check if the server returned a redirection
        if 300 <= httpResp.status < 400:
            redirectHeader = httpResp.getheader('Location', None)
                
            o = urlparse(redirectHeader)
            if o.scheme == 'https':
                return (httpResp.status, redirectHeader)
        return (httpResp.status, redirectHeader)
