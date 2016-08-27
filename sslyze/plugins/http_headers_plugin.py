# -*- coding: utf-8 -*-
"""Plugin to test the server for the presence of the HTTP Strict Transport Security and HTTP Public Key Pinning
headers.
"""

import Cookie
from urlparse import urlparse
from xml.etree.ElementTree import Element

from sslyze.plugins import plugin_base
from sslyze.plugins.certificate_info_plugin import CertInfoFullResult, Certificate
from sslyze.plugins.plugin_base import PluginResult
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.utils.http_response_parser import parse_http_response


class HttpHeadersPlugin(plugin_base.PluginBase):

    interface = plugin_base.PluginInterface(title="HttpHeadersPlugin", description='')
    interface.add_command(
        command="http_headers",
        help="Checks for the HTTP Strict Transport Security (HSTS) and HTTP Public Key Pinning (HPKP) HTTP headers "
             "within the response sent back by the server(s). Also computes the HPKP pins for the server(s)' current "
             "certificate chain."
    )


    def process_task(self, server_info, command, options_dict=None):

        if server_info.tls_wrapped_protocol not in [TlsWrappedProtocolEnum.PLAIN_TLS, TlsWrappedProtocolEnum.HTTPS]:
            raise ValueError('Cannot test for HTTP headers on a StartTLS connection.')

        hsts_header, hpkp_header, certificate_chain = self._get_hsts_header(server_info)
        return HstsResult(server_info, command, options_dict, hsts_header, hpkp_header, certificate_chain)



    MAX_REDIRECT = 5

    def _get_hsts_header(self, server_info):
        certificate_chain = None
        hsts_header = None
        hpkp_header = None
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
            certificate_chain = ssl_connection.get_peer_cert_chain()

            ssl_connection.write(http_get_format(http_path, server_info.hostname, http_append))
            http_resp = parse_http_response(ssl_connection)
            ssl_connection.close()
            
            if http_resp.version == 9 :
                # HTTP 0.9 => Probably not an HTTP response
                raise ValueError('Server did not return an HTTP response')
            else:
                hsts_header = http_resp.getheader('strict-transport-security', None)
                hpkp_header = http_resp.getheader('public-key-pins', None)
                if hpkp_header is None:
                    hpkp_header = http_resp.getheader('public-key-pins-only', None)

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

        return hsts_header, hpkp_header, certificate_chain


class HstsResult(PluginResult):
    """The result of running --hsts on a specific server.

    Attributes:
        hsts_header (str): The content of the HSTS header returned by the server; None if no HSTS header was returned.
    """

    COMMAND_TITLE = 'HTTP Strict Transport Security'

    def __init__(self, server_info, plugin_command, plugin_options, hsts_header, hpkp_header, certificate_chain):
        super(HstsResult, self).__init__(server_info, plugin_command, plugin_options)
        self.hsts_header = hsts_header
        self.hpkp_header = hpkp_header

        # Hack: use function in CertificateInfoPlugin to get the verified certificate chain so we can check the pins
        self.verified_certificate_chain = CertInfoFullResult._build_verified_certificate_chain(
            [Certificate(x509_cert) for x509_cert in certificate_chain])


    PIN_TXT_FORMAT = '      {0:<80}{1}'.format

    def as_text(self):
        txt_result = [self.PLUGIN_TITLE_FORMAT(self.COMMAND_TITLE)]

        if self.hsts_header:
            txt_result.append(self.FIELD_FORMAT("OK - HSTS header received:", self.hsts_header))
        else:
            txt_result.append(self.FIELD_FORMAT("NOT SUPPORTED - Server did not send an HSTS header", ""))

        computed_hpkp_pins_text = ['', self.PLUGIN_TITLE_FORMAT('Computed HPKP Pins for Current Chain')]
        server_pin_list = []
        if self.verified_certificate_chain:
            for index, cert in enumerate(self.verified_certificate_chain, start=0):
                cert_subject = CertInfoFullResult._extract_subject_cn_or_oun(cert)
                computed_hpkp_pins_text.append(self.PIN_TXT_FORMAT(('{} - {}'.format(index, cert_subject)),
                                                                   cert.hpkp_pin))
                server_pin_list.append(cert.hpkp_pin)
        else:
            computed_hpkp_pins_text.append(self.FIELD_FORMAT("ERROR - Could not build verified chain", ""))

        txt_result.extend(['', self.PLUGIN_TITLE_FORMAT('HTTP Public Key Pinning (HPKP)')])
        if self.hpkp_header:
            # Parse the header
            configured_pin_list = []
            hpkp_max_age = None
            for element in self.hpkp_header.split(';'):
                if 'pin-sha256' in element:
                    hpkp_pin = element.split('"')[1].strip()
                    configured_pin_list.append(hpkp_pin)
                elif 'max-age' in element:
                    hpkp_max_age = element.split('=')[1].strip()

            txt_result.append(self.FIELD_FORMAT("Max Age:", hpkp_max_age))
            txt_result.append(self.FIELD_FORMAT("Configured Pins:", ', '.join(configured_pin_list)))

            if self.verified_certificate_chain:
                was_pin_found = False
                for pin in configured_pin_list:
                    if pin in server_pin_list:
                        was_pin_found = True
                        break

                pin_validation_txt = 'OK - One of the configured pins was found in the certificate chain' \
                    if was_pin_found \
                    else 'FAILED - Could NOT find any of the configured pins in the certificate chain!'
                txt_result.append(self.FIELD_FORMAT("Pinning Validation:", pin_validation_txt))


                has_backup_pin = set(configured_pin_list) != set(server_pin_list)
                backup_txt = 'OK - Backup pin found in the configured pins' \
                    if has_backup_pin \
                    else 'FAILED - No backup pin found: all the configured pins are in the certificate chain!'
                txt_result.append(self.FIELD_FORMAT("Backup Pin:", backup_txt))

        else:
            txt_result.append(self.FIELD_FORMAT("NOT SUPPORTED - Server did not send an HPKP header", ""))

        # Dispay computed HPKP pins last
        txt_result.extend(computed_hpkp_pins_text)

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
