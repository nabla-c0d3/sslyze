import unittest

import pickle

from sslyze.plugins.openssl_cipher_suites_plugin import OpenSslCipherSuitesPlugin, Sslv20ScanCommand, \
    Sslv30ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from tests.openssl_server import LegacyOpenSslServer, ModernOpenSslServer, ClientAuthConfigEnum


class OpenSslCipherSuitesPluginTestCase(unittest.TestCase):

    @unittest.skipIf(not LegacyOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_sslv2_enabled(self):
        with LegacyOpenSslServer() as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

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

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_sslv2_disabled(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Sslv20ScanCommand())

        self.assertIsNone(plugin_result.preferred_cipher)
        self.assertFalse(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    @unittest.skipIf(not LegacyOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_sslv3_enabled(self):
        with LegacyOpenSslServer() as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port)
            server_info = server_test.perform()

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

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_sslv3_disabled(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Sslv30ScanCommand())

        self.assertIsNone(plugin_result.preferred_cipher)
        self.assertFalse(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_tlsv1_0_enabled(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv10ScanCommand())

        self.assertTrue(plugin_result.preferred_cipher)
        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
                          'TLS_RSA_WITH_3DES_EDE_CBC_SHA'},
                         set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_tlsv1_0_disabled(self):
        server_test = ServerConnectivityTester(hostname='success.trendmicro.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv10ScanCommand())

        self.assertIsNone(plugin_result.preferred_cipher)
        self.assertFalse(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_tlsv1_1_enabled(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv11ScanCommand())

        self.assertTrue(plugin_result.preferred_cipher)
        self.assertTrue(plugin_result.accepted_cipher_list)
        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                          'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
                          'TLS_RSA_WITH_3DES_EDE_CBC_SHA'},
                         set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_tlsv1_2_enabled(self):
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        # Also do full HTTP connections
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand(http_get=True))

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

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_null_cipher_suites(self):
        server_test = ServerConnectivityTester(hostname='null.badssl.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_ECDH_anon_WITH_AES_256_CBC_SHA', 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
                          'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA', 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
                          'TLS_DH_anon_WITH_AES_256_CBC_SHA', 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
                          'TLS_DH_anon_WITH_AES_128_CBC_SHA256', 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
                          'TLS_DH_anon_WITH_AES_128_GCM_SHA256', 'TLS_DH_anon_WITH_SEED_CBC_SHA',
                          'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_NULL_SHA',
                          'TLS_ECDH_anon_WITH_NULL_SHA', 'TLS_RSA_WITH_NULL_SHA256', 'TLS_RSA_WITH_NULL_SHA'},
                          set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_rc4_cipher_suites(self):
        server_test = ServerConnectivityTester(hostname='rc4.badssl.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_SHA'},
                         set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_rc4_md5_cipher_suites(self):
        server_test = ServerConnectivityTester(hostname='rc4-md5.badssl.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual({'TLS_RSA_WITH_RC4_128_MD5'},
                         set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_follows_client_cipher_suite_preference(self):
        # Google.com does not follow client cipher suite preference
        server_test = ServerConnectivityTester(hostname='www.google.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        self.assertTrue(plugin_result.preferred_cipher)
        self.assertTrue(plugin_result.accepted_cipher_list)
        
        # Sogou.com follows client cipher suite preference
        server_test = ServerConnectivityTester(hostname='www.sogou.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        self.assertIsNone(plugin_result.preferred_cipher)
        self.assertTrue(plugin_result.accepted_cipher_list)

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_smtp_post_handshake_response(self):
        server_test = ServerConnectivityTester(
            hostname='smtp.gmail.com',
            port=587,
            tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP
        )
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_tls_1_3_cipher_suites(self):
        server_test = ServerConnectivityTester(hostname='www.cloudflare.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv13ScanCommand())

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEqual(
            {'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256'},
            set(accepted_cipher_name_list)
        )

    @unittest.skipIf(not ModernOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_succeeds_when_client_auth_failed_tls_1_2(self):
        # Given a TLS 1.2 server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client does NOT provide a client certificate
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            # OpenSslCipherSuitesPlugin works even when a client cert was not supplied
            plugin = OpenSslCipherSuitesPlugin()
            plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        self.assertTrue(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    @unittest.skipIf(not ModernOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_succeeds_when_client_auth_failed_tls_1_3(self):
        # Given a TLS 1.3 server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client does NOT provide a client certificate
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            # OpenSslCipherSuitesPlugin works even when a client cert was not supplied
            plugin = OpenSslCipherSuitesPlugin()
            plugin_result = plugin.process_task(server_info, Tlsv13ScanCommand())

        self.assertTrue(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
