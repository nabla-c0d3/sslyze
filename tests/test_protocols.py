# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import socket
import unittest

from nassl.ssl_client import OpenSslVersionEnum

from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin, CertificateInfoScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import TlsWrappedProtocolEnum, ClientAuthenticationServerConfigurationEnum


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


class ProtocolsTestCase(unittest.TestCase):

    def test_smtp_custom_port(self):
        server_test = ServerConnectivityTester(
            hostname='smtp.gmail.com',
            port=587,
            tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP
        )
        server_info = server_test.perform()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertGreaterEqual(len(plugin_result.certificate_chain), 1)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    @unittest.skipIf(not _is_ipv6_available(), 'IPv6 not available')
    def test_ipv6(self):
        server_test = ServerConnectivityTester(hostname='www.google.com', ip_address='2607:f8b0:4005:804::2004')
        server_info = server_test.perform()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertGreaterEqual(len(plugin_result.certificate_chain), 1)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_international_names(self):
        server_test = ServerConnectivityTester(hostname='www.sociétégénérale.com')
        server_info = server_test.perform()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertGreaterEqual(len(plugin_result.certificate_chain), 1)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_xmpp_to(self):
        server_test = ServerConnectivityTester(
            hostname='talk.google.com',
            tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_XMPP,
            xmpp_to_hostname='gmail.com'
        )
        server_info = server_test.perform()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertGreaterEqual(len(plugin_result.certificate_chain), 1)

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
            server_test = ServerConnectivityTester(hostname=hostname, tls_wrapped_protocol=protocol)
            server_info = server_test.perform()

            plugin = CertificateInfoPlugin()
            plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

            self.assertTrue(plugin_result.as_text())
            self.assertTrue(plugin_result.as_xml())

    def test_optional_client_authentication(self):
        server_test = ServerConnectivityTester(hostname='client.badssl.com')
        server_info = server_test.perform()
        self.assertEqual(server_info.client_auth_requirement, ClientAuthenticationServerConfigurationEnum.OPTIONAL)

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_tls_1_only(self):
        server_test = ServerConnectivityTester(hostname='tls-v1-0.badssl.com', port=1010)
        server_info = server_test.perform()
        self.assertEqual(server_info.highest_ssl_version_supported, OpenSslVersionEnum.TLSV1)
