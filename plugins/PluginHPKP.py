#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:         PluginHPKP.py
# Purpose:      Checks if the server supports Public Key Pinning Extension
#               for HTTP
#
# Author:       Aaron Zauner <azet@azet.org>
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

from xml.etree.ElementTree import Element
from utils.HTTPResponseParser import parse_http_response
from utils.SSLyzeSSLConnection import create_sslyze_connection
from plugins import PluginBase
from urlparse import urlparse
import Cookie


class PluginHPKP(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginHPKP", description=(''))
    interface.add_command(
        command="hpkp",
        help="Checks support for Public Key Pinning Extension for HTTP.",
        dest=None)


    def process_task(self, target, command, args):
        if self._shared_settings['starttls']:
            raise Exception('Cannot use --hpkp with --starttls.')

        hpkp_supported = self._get_hpkp_header(target)
        if hpkp_supported:
            hpkp_timeout = hpkp_supported
            hpkp_supported = True

        # Text output
        cmd_title = 'Public Key Pinning Extension for HTTP'
        txt_result = [self.PLUGIN_TITLE_FORMAT(cmd_title)]
        if hpkp_supported:
            txt_result.append(self.FIELD_FORMAT("OK - HPKP header received:", hpkp_timeout))
        else:
            txt_result.append(self.FIELD_FORMAT("NOT SUPPORTED - Server did not send a HPKP header.", ""))

        # XML output
        xml_hpkp_attr = {'sentHpkpHeader': str(hpkp_supported)}
        if hpkp_supported:
            xml_hpkp_attr['hpkpHeaderValue'] = hpkp_timeout
        xml_hpkp = Element('hpkp', attrib = xml_hpkp_attr)

        xml_result = Element('hpkp', title = cmd_title)
        xml_result.append(xml_hpkp)

        return PluginBase.PluginResult(txt_result, xml_result)



    def _get_hpkp_header(self, target):

        hpkpHeader = None
        MAX_REDIRECT = 5
        nb_redirect = 0
        httpGetFormat = 'GET {0} HTTP/1.0\r\nHost: {1}\r\n{2}Connection: close\r\n\r\n'.format
        httpPath = '/'
        httpAppend = ''
        
        while nb_redirect < MAX_REDIRECT:
            sslConn = create_sslyze_connection(target, self._shared_settings)
            
            # Perform the SSL handshake
            sslConn.connect()
            
            sslConn.write(httpGetFormat(httpPath, target[0], httpAppend))
            httpResp = parse_http_response(sslConn.read(2048))
            sslConn.close()
            
            if httpResp.version == 9 :
                # HTTP 0.9 => Probably not an HTTP response
                raise Exception('Server did not return an HTTP response')
            else:
                hpkpHeader = httpResp.getheader('Public-Key-Pins', None)


            # If there was no HPKP header, check if the server returned a redirection
            if hpkpHeader is None and 300 <= httpResp.status < 400:
                redirectHeader = httpResp.getheader('Location', None)
                cookieHeader = httpResp.getheader('Set-Cookie', None)
                
                if redirectHeader is None:
                    break
                
                o = urlparse(redirectHeader)
                httpPath = o.path
                
                # Handle absolute redirection URL
                if o.hostname:
                    if o.port:
                        port = o.port
                    else:
                        if o.scheme == 'https':
                            port = 443
                        elif o.scheme == 'http':
                            # We would have to use urllib for http: URLs
                            raise Exception("Error: server sent a redirection to HTTP.")
                        else:
                            port = target[2]
                        
                    target = (o.hostname, o.hostname, port, target[3])

                # Handle cookies
                if cookieHeader:
                    cookie = Cookie.SimpleCookie(cookieHeader)

                    if cookie:
                        httpAppend = 'Cookie:' + cookie.output(attrs=[], header='', sep=';') + '\r\n'

                nb_redirect+=1
            else:
                # If the server did not return a redirection just give up
                break

        
        return hpkpHeader


