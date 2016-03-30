# -*- coding: utf-8 -*-
"""Plugin to test the server for the presence of the HTTP Strict Transport Security header.
"""

import Cookie
from urlparse import urlparse
from xml.etree.ElementTree import Element

from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginResult
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.utils.http_response_parser import parse_http_response


class HstsPlugin(plugin_base.PluginBase):

    interface = plugin_base.PluginInterface(title="HstsPlugin", description='')
    interface.add_command(
        command="hsts",
        help="Checks support for HTTP Strict Transport Security (HSTS) by collecting any Strict-Transport-Security "
             "field present in the HTTP response sent back by the server(s)."
    )


    def process_task(self, server_info, command, options_dict=None):

        if server_info.tls_wrapped_protocol not in [TlsWrappedProtocolEnum.PLAIN_TLS, TlsWrappedProtocolEnum.HTTPS]:
            raise ValueError('Cannot test for HSTS on a StartTLS connection.')

        hsts_header = self._get_hsts_header(server_info)
        return HstsResult(server_info, command, options_dict, hsts_header)


    MAX_REDIRECT = 5

    def _get_hsts_header(self, server_info):

        hsts_header = None
        nb_redirect = 0
        http_get_format = 'GET {0} HTTP/1.0\r\nHost: {1}\r\n{2}Connection: close\r\n\r\n'.format
        http_path = '/'
        http_append = ''

        while nb_redirect < self.MAX_REDIRECT:
            # Always use a new connection as some servers always close the connection after sending back an HTTP
            # response
            ssl_connection = server_info.get_preconfigured_ssl_connection()

            # Perform the SSL handshake
            ssl_connection.connect()

            ssl_connection.write(http_get_format(http_path, server_info.hostname, http_append))
            http_resp = parse_http_response(ssl_connection)
            ssl_connection.close()
            
            if http_resp.version == 9 :
                # HTTP 0.9 => Probably not an HTTP response
                raise ValueError('Server did not return an HTTP response')
            else:
                hsts_header = http_resp.getheader('strict-transport-security', None)

            # If there was no HSTS header, check if the server returned a redirection
            if hsts_header is None and 300 <= http_resp.status < 400:
                redirect_header = http_resp.getheader('Location', None)
                cookie_header = http_resp.getheader('Set-Cookie', None)
                
                if redirect_header is None:
                    break
                o = urlparse(redirect_header)
                
                # Handle absolute redirection URL but only allow redirections to the same domain and port
                if o.hostname and o.hostname != server_info.hostname:
                    break
                else:
                    http_path = o.path
                    if o.scheme == 'http':
                        # We would have to use urllib for http: URLs
                        break

                # Handle cookies
                if cookie_header:
                    cookie = Cookie.SimpleCookie(cookie_header)
                    if cookie:
                        http_append = 'Cookie:' + cookie.output(attrs=[], header='', sep=';') + '\r\n'

                nb_redirect+=1
            else:
                # If the server did not return a redirection just give up
                break

        return hsts_header


class HstsResult(PluginResult):
    """The result of running --hsts on a specific server.

    Attributes:
        hsts_header (str): The content of the HSTS header returned by the server; None if no HSTS header was returned.
    """

    COMMAND_TITLE = 'HTTP Strict Transport Security'

    def __init__(self, server_info, plugin_command, plugin_options, hsts_header):
        super(HstsResult, self).__init__(server_info, plugin_command, plugin_options)
        self.hsts_header = hsts_header


    def as_text(self):
        txt_result = [self.PLUGIN_TITLE_FORMAT(self.COMMAND_TITLE)]
        if self.hsts_header:
            txt_result.append(self.FIELD_FORMAT("OK - HSTS header received:", self.hsts_header))
        else:
            txt_result.append(self.FIELD_FORMAT("NOT SUPPORTED - Server did not send an HSTS header.", ""))
        return txt_result


    def as_xml(self):
        xml_result = Element(self.plugin_command, title=self.COMMAND_TITLE)

        is_hsts_supported = True if self.hsts_header else False
        xml_hsts_attr = {'isSupported': str(is_hsts_supported)}
        if is_hsts_supported:
            # Do some light parsing of the HSTS header
            hsts_header_split = self.hsts_header.split('max-age=')[1].split(';')
            hsts_max_age = hsts_header_split[0].strip()
            hsts_subdomains = False
            if len(hsts_header_split) > 1 and 'includeSubdomains' in hsts_header_split[1]:
                hsts_subdomains = True

            xml_hsts_attr['maxAge'] = hsts_max_age
            xml_hsts_attr['includeSubdomains'] = str(hsts_subdomains)

        xml_hsts = Element('httpStrictTransportSecurity', attrib=xml_hsts_attr)
        xml_result.append(xml_hsts)
        return xml_result
