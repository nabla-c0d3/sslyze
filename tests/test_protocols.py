# -*- coding: utf-8 -*-
import socket
import unittest

from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError, \
    ClientAuthenticationServerConfigurationEnum
from sslyze.ssl_settings import TlsWrappedProtocolEnum, HttpConnectTunnelingSettings


class ProtocolsTestCase(unittest.TestCase):


    def test_smtp_custom_port(self):
        server_info = ServerConnectivityInfo(hostname='smtp.gmail.com', port=587,
                                             tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP)
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertEquals(len(plugin_result.certificate_chain), 3)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    @staticmethod
    def _is_ipv6_available():
        has_ipv6 = False
        s = socket.socket(socket.AF_INET6)
        try:
            s.connect(('2607:f8b0:4005:804::2004', 443))
            has_ipv6 = True
        except:
            pass
        return has_ipv6


    def test_ipv6(self):
        if not self._is_ipv6_available():
            print 'WARNING: IPv6 not available - skipping test'
            return

        server_info = ServerConnectivityInfo(hostname='www.google.com', ip_address='2607:f8b0:4005:804::2004')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertEquals(len(plugin_result.certificate_chain), 3)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    def test_international_names(self):
        server_info = ServerConnectivityInfo(hostname=u'www.sociétégénérale.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertEquals(len(plugin_result.certificate_chain), 3)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    def test_xmpp_to(self):
        server_info = ServerConnectivityInfo(hostname='talk.google.com',
                                             tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_XMPP,
                                             xmpp_to_hostname='gmail.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertEquals(len(plugin_result.certificate_chain), 3)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    def test_starttls(self):
        for hostname, protocol in [('imap.comcast.net', TlsWrappedProtocolEnum.STARTTLS_IMAP),
                                   ('pop.comcast.net', TlsWrappedProtocolEnum.STARTTLS_POP3),
                                   ('ldap.virginia.edu', TlsWrappedProtocolEnum.STARTTLS_LDAP),
                                   ('jabber.org', TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER)]:

            server_info = ServerConnectivityInfo(hostname=hostname, tls_wrapped_protocol=protocol)
            server_info.test_connectivity_to_server()

            plugin = CertificateInfoPlugin()
            plugin_result = plugin.process_task(server_info, 'certinfo_basic')

            self.assertTrue(plugin_result.as_text())
            self.assertTrue(plugin_result.as_xml())


    def test_optional_client_authentication(self):
        for hostname in ['auth.startssl.com', 'xnet-eu.intellij.net']:
            server_info = ServerConnectivityInfo(hostname=hostname)
            server_info.test_connectivity_to_server()
            self.assertEquals(server_info.client_auth_requirement, ClientAuthenticationServerConfigurationEnum.OPTIONAL)

            plugin = CertificateInfoPlugin()
            plugin_result = plugin.process_task(server_info, 'certinfo_basic')

            self.assertTrue(plugin_result.as_text())
            self.assertTrue(plugin_result.as_xml())
