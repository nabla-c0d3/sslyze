# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest
import logging
import platform
import pickle

from sslyze.plugins.openssl_cipher_suites_plugin import OpenSslCipherSuitesPlugin, Sslv20ScanCommand, Sslv30ScanCommand, \
    Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from tests import SslyzeTestCase
from tests.plugin_tests.openssl_server import NOT_ON_LINUX_64BIT
from tests.plugin_tests.openssl_server import VulnerableOpenSslServer


class OpenSslCipherSuitesPluginTestCase(unittest.TestCase):

    def _get_plugin_result(self, hostname, command=Tlsv12ScanCommand()):
        server_info = ServerConnectivityInfo(hostname=hostname)
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, command)

        return plugin_result

    def _test_plugin_outputs(self, plugin_result):
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    @unittest.skipIf(NOT_ON_LINUX_64BIT,
                     'test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits')
    def test_sslv2_enabled(self):
        with VulnerableOpenSslServer() as server:
            server_info = ServerConnectivityInfo(hostname=server.hostname, ip_address=server.ip_address,
                                                 port=server.port)
            server_info.test_connectivity_to_server()

            plugin = OpenSslCipherSuitesPlugin()
            plugin_result = plugin.process_task(server_info, Sslv20ScanCommand())

        # The embedded server does not have a preference
        self.assertFalse(plugin_result.preferred_cipher)

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'SSL_CK_RC4_128_EXPORT40_WITH_MD5', 'SSL_CK_IDEA_128_CBC_WITH_MD5',
                          'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5', 'SSL_CK_DES_192_EDE3_CBC_WITH_MD5',
                          'SSL_CK_DES_192_EDE3_CBC_WITH_MD5', 'SSL_CK_RC4_128_WITH_MD5',
                          'SSL_CK_RC2_128_CBC_WITH_MD5', 'SSL_CK_DES_64_CBC_WITH_MD5'},
                         set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.accepted_cipher_list)
        self.assertFalse(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self._test_plugin_outputs(plugin_result)

    def test_sslv2_disabled(self):
        plugin_result = self._get_plugin_result('www.google.com', Sslv20ScanCommand())

        self.assertIsNone(plugin_result.preferred_cipher)
        self.assertFalse(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self._test_plugin_outputs(plugin_result)

    @unittest.skipIf(NOT_ON_LINUX_64BIT,
                     'test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits')
    def test_sslv3_enabled(self):
        with VulnerableOpenSslServer() as server:
            server_info = ServerConnectivityInfo(hostname=server.hostname, ip_address=server.ip_address,
                                                 port=server.port)
            server_info.test_connectivity_to_server()

            plugin = OpenSslCipherSuitesPlugin()
            plugin_result = plugin.process_task(server_info, Sslv30ScanCommand())

        # The embedded server does not have a preference
        self.assertFalse(plugin_result.preferred_cipher)
        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                          'TLS_DH_anon_WITH_AES_128_CBC_SHA', 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
                          'TLS_DH_anon_WITH_SEED_CBC_SHA', 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
                          'TLS_ECDHE_RSA_WITH_NULL_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
                          'TLS_DH_anon_WITH_AES_256_CBC_SHA',
                          'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA', 'TLS_ECDH_anon_WITH_RC4_128_SHA',
                          'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
                          'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5', 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
                          'TLS_ECDH_anon_WITH_NULL_SHA',
                          'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA',
                          'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_NULL_MD5',
                          'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA', 'TLS_DH_anon_WITH_DES_CBC_SHA',
                          'TLS_RSA_WITH_SEED_CBC_SHA', 'TLS_RSA_WITH_DES_CBC_SHA',
                          'TLS_ECDH_anon_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
                          'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                          'TLS_RSA_WITH_RC4_128_MD5', 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
                          'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_NULL_SHA',
                          'TLS_RSA_WITH_IDEA_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_DH_anon_WITH_RC4_128_MD5'},
                         set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self._test_plugin_outputs(plugin_result)

    def test_sslv3_disabled(self):
        plugin_result = self._get_plugin_result('www.google.com', Sslv30ScanCommand())

        self.assertIsNone(plugin_result.preferred_cipher)
        self.assertFalse(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_tlsv1_0_enabled(self):
        plugin_result = self._get_plugin_result('www.google.com', Tlsv10ScanCommand())

        self.assertTrue(plugin_result.preferred_cipher)
        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
                          'TLS_RSA_WITH_3DES_EDE_CBC_SHA'},
                         set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self._test_plugin_outputs(plugin_result)

    def test_tlsv1_0_disabled(self):
        # TBD
        pass


    def test_tlsv1_1_enabled(self):
        plugin_result = self._get_plugin_result('www.google.com', Tlsv11ScanCommand())

        self.assertTrue(plugin_result.preferred_cipher)
        self.assertTrue(plugin_result.accepted_cipher_list)
        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
                          'TLS_RSA_WITH_3DES_EDE_CBC_SHA'},
                         set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self._test_plugin_outputs(plugin_result)

    def test_tlsv1_2_enabled(self):
        plugin_result = self._get_plugin_result('www.google.com', Tlsv12ScanCommand(http_get=True))

        self.assertTrue(plugin_result.preferred_cipher)
        self.assertTrue(plugin_result.accepted_cipher_list)
        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]

        self.assertEqual({'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
                          'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                          'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA',
                          'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                          'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'},
                         set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self._test_plugin_outputs(plugin_result)

    def test_null_cipher_suites(self):
        plugin_result = self._get_plugin_result('null.badssl.com')

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_ECDH_anon_WITH_AES_256_CBC_SHA', 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
                          'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA', 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
                          'TLS_DH_anon_WITH_AES_256_CBC_SHA', 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
                          'TLS_DH_anon_WITH_AES_128_CBC_SHA256', 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
                          'TLS_DH_anon_WITH_AES_128_GCM_SHA256', 'TLS_DH_anon_WITH_SEED_CBC_SHA',
                          'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_NULL_SHA',
                          'TLS_ECDH_anon_WITH_NULL_SHA', 'TLS_RSA_WITH_NULL_SHA256', 'TLS_RSA_WITH_NULL_SHA'},
                          set(accepted_cipher_name_list))

        self._test_plugin_outputs(plugin_result)

    def test_rc4_cipher_suites(self):
        plugin_result = self._get_plugin_result('rc4.badssl.com')

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_SHA'},
                         set(accepted_cipher_name_list))

        self._test_plugin_outputs(plugin_result)

    def test_rc4_md5_cipher_suites(self):
        plugin_result = self._get_plugin_result('rc4-md5.badssl.com')

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_RSA_WITH_RC4_128_MD5'},
                         set(accepted_cipher_name_list))

        self._test_plugin_outputs(plugin_result)

    def test_follows_client_cipher_suite_preference(self):
        # Google.com does not follow client cipher suite preference
        plugin_result = self._get_plugin_result('www.google.com')

        self.assertTrue(plugin_result.preferred_cipher)
        self.assertTrue(plugin_result.accepted_cipher_list)
        
        # Sogou.com follows client cipher suite preference
        server_info = ServerConnectivityInfo(hostname='www.sogou.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        self._test_plugin_outputs(plugin_result)

    def test_smtp_post_handshake_response(self):
        server_info = ServerConnectivityInfo(hostname='smtp.gmail.com', port=587,
                                             tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP)
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        self._test_plugin_outputs(plugin_result)

    def test_tls_1_3_cipher_suites(self):
        server_info = ServerConnectivityInfo(hostname='www.cloudflare.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv13ScanCommand())

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]

        # TODO(AD): Update to TLS 1.3 draft 23 and re-enable this test
        return
        self.assertEqual({'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256'},
                         set(accepted_cipher_name_list))
