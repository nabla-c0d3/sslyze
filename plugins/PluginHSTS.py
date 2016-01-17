#!/usr/bin/env python2.7
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
# Author:       tecknicaltom, joachims, alban
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
from utils.HTTPResponseParser import parse_http_response
from plugins import PluginBase
from urlparse import urlparse
import Cookie

from utils.ServersConnectivityTester import StartTlsProtocolEnum


class PluginHSTS(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginHSTS", description=(''))
    interface.add_command(
        command="hsts",
        help="Checks support for HTTP Strict Transport Security "
             "(HSTS) by collecting any Strict-Transport-Security field present in "
             "the HTTP response sent back by the server(s).",
        dest=None)


    def process_task(self, server_info, command, args):
        if server_info.starttls_protocol != StartTlsProtocolEnum.NO_STARTTLS:
            raise ValueError('Cannot test for HSTS on a StartTLS connection.')

        hsts_header = self._get_hsts_header(server_info)
        hsts_supported = False
        if hsts_header:
            hsts_supported = True

        # Text output
        cmd_title = 'HTTP Strict Transport Security'
        txt_result = [self.PLUGIN_TITLE_FORMAT(cmd_title)]
        if hsts_supported:
            txt_result.append(self.FIELD_FORMAT("OK - HSTS header received:", hsts_header))
        else:
            txt_result.append(self.FIELD_FORMAT("NOT SUPPORTED - Server did not send an HSTS header.", ""))

        # XML output
        xml_hsts_attr = {'isSupported': str(hsts_supported)}
        if hsts_supported:
            # Do some light parsing of the HSTS header
            hsts_header_split = hsts_header.split('max-age=')[1].split(';')
            hsts_max_age = hsts_header_split[0].strip()
            hsts_subdomains = False
            if len(hsts_header_split) > 1 and 'includeSubdomains' in hsts_header_split[1]:
                hsts_subdomains = True

            xml_hsts_attr['maxAge'] = hsts_max_age
            xml_hsts_attr['includeSubdomains'] = str(hsts_subdomains)

        xml_hsts = Element('httpStrictTransportSecurity', attrib=xml_hsts_attr)
        xml_result = Element('hsts', title=cmd_title)
        xml_result.append(xml_hsts)

        return PluginBase.PluginResult(txt_result, xml_result)


    def _get_hsts_header(self, server_info):

        hstsHeader = None
        MAX_REDIRECT = 5
        nb_redirect = 0
        httpGetFormat = 'GET {0} HTTP/1.0\r\nHost: {1}\r\n{2}Connection: close\r\n\r\n'.format
        httpPath = '/'
        httpAppend = ''

        sslConn = server_info.get_preconfigured_ssl_connection()
        # Perform the SSL handshake
        sslConn.connect()

        while nb_redirect < MAX_REDIRECT:

            sslConn.write(httpGetFormat(httpPath, server_info.hostname, httpAppend))
            httpResp = parse_http_response(sslConn)
            
            if httpResp.version == 9 :
                # HTTP 0.9 => Probably not an HTTP response
                raise ValueError('Server did not return an HTTP response')
            else:
                hstsHeader = httpResp.getheader('strict-transport-security', False)

            # If there was no HSTS header, check if the server returned a redirection
            if hstsHeader is None and 300 <= httpResp.status < 400:
                redirectHeader = httpResp.getheader('Location', None)
                cookieHeader = httpResp.getheader('Set-Cookie', None)
                
                if redirectHeader is None:
                    break
                o = urlparse(redirectHeader)
                print 'redirection'
                
                # Handle absolute redirection URL but only allow redirections to the same domain and port
                if o.hostname and o.hostname != server_info.hostname:
                    break
                else:
                    httpPath = o.path
                    if o.scheme == 'http':
                        # We would have to use urllib for http: URLs
                        raise ValueError("Error: server sent a redirection to HTTP.")

                # Handle cookies
                if cookieHeader:
                    cookie = Cookie.SimpleCookie(cookieHeader)
                    if cookie:
                        httpAppend = 'Cookie:' + cookie.output(attrs=[], header='', sep=';') + '\r\n'

                nb_redirect+=1
            else:
                # If the server did not return a redirection just give up
                break

        sslConn.close()
        return hstsHeader


