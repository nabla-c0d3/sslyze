# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import socket
import unittest
import logging

from nassl.ssl_client import OpenSslVersionEnum

from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin, CertificateInfoScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo, ClientAuthenticationServerConfigurationEnum
from sslyze.ssl_settings import TlsWrappedProtocolEnum


class ProtocolsTestCase(unittest.TestCase):

    def test_smtp_custom_port(self):
        server_info = ServerConnectivityInfo(hostname='smtp.gmail.com', port=587,
                                             tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP)
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertEqual(len(plugin_result.certificate_chain), 2)

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
        finally:
            s.close()
        return has_ipv6

    def test_ipv6(self):
        if not self._is_ipv6_available():
            logging.warning('WARNING: IPv6 not available - skipping test')
            return

        server_info = ServerConnectivityInfo(hostname='www.google.com', ip_address='2607:f8b0:4005:804::2004')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertEqual(len(plugin_result.certificate_chain), 3)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_international_names(self):
        server_info = ServerConnectivityInfo(hostname='www.sociétégénérale.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertEqual(len(plugin_result.certificate_chain), 2)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_xmpp_to(self):
        server_info = ServerConnectivityInfo(hostname='talk.google.com',
                                             tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_XMPP,
                                             xmpp_to_hostname='gmail.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertEqual(len(plugin_result.certificate_chain), 2)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_starttls(self):
        for hostname, protocol in [
            ('imap.comcast.net', TlsWrappedProtocolEnum.STARTTLS_IMAP),
            ('pop.comcast.net', TlsWrappedProtocolEnum.STARTTLS_POP3),
            ('ldap.uchicago.edu', TlsWrappedProtocolEnum.STARTTLS_LDAP),
            ('jabber.org', TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER),
            # Some Heroku Postgres instance I created
            ('ec2-54-75-226-17.eu-west-1.compute.amazonaws.com', TlsWrappedProtocolEnum.STARTTLS_POSTGRES)
        ]:
            server_info = ServerConnectivityInfo(hostname=hostname, tls_wrapped_protocol=protocol)
            server_info.test_connectivity_to_server()

            plugin = CertificateInfoPlugin()
            plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

            self.assertTrue(plugin_result.as_text())
            self.assertTrue(plugin_result.as_xml())

    def test_optional_client_authentication(self):
        server_info = ServerConnectivityInfo(hostname='client.badssl.com')
        server_info.test_connectivity_to_server()
        self.assertEqual(server_info.client_auth_requirement, ClientAuthenticationServerConfigurationEnum.OPTIONAL)

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_tls_1_3_only(self):
        server_info = ServerConnectivityInfo(hostname='www.cloudflare.com')
        server_info.test_connectivity_to_server()
        self.assertEqual(server_info.highest_ssl_version_supported, OpenSslVersionEnum.TLSV1_3)

    def test_tls_1_only(self):
        server_info = ServerConnectivityInfo(hostname='tls-v1-0.badssl.com', port=1010)
        server_info.test_connectivity_to_server()
        self.assertEqual(server_info.highest_ssl_version_supported, OpenSslVersionEnum.TLSV1)
