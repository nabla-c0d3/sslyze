import unittest
from sslyze.plugins.openssl_cipher_suites_plugin import OpenSslCipherSuitesPlugin
from sslyze.server_connectivity import ServerConnectivityInfo


class OpenSslCipherSuitesPluginTestCase(unittest.TestCase):

    def test_sslv2_enabled(self):
        # TBD
        pass

    def test_sslv2_disabled(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, 'sslv2')

        self.assertIsNone(plugin_result.preferred_cipher)
        self.assertFalse(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_sslv3_enabled(self):
        # TBD
        pass

    def test_sslv3_disabled(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, 'sslv3')

        self.assertIsNone(plugin_result.preferred_cipher)
        self.assertFalse(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_tlsv1_0_enabled(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, 'tlsv1')

        self.assertTrue(plugin_result.preferred_cipher)
        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEquals({'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                           'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
                           'TLS_RSA_WITH_3DES_EDE_CBC_SHA'},
                          set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_tlsv1_0_disabled(self):
        # TBD
        pass


    def test_tlsv1_1_enabled(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, 'tlsv1_1')

        self.assertTrue(plugin_result.preferred_cipher)

        self.assertTrue(plugin_result.accepted_cipher_list)
        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEquals({'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                           'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
                           'TLS_RSA_WITH_3DES_EDE_CBC_SHA'},
                          set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    def test_tlsv1_2_enabled(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, 'tlsv1_2')

        self.assertTrue(plugin_result.preferred_cipher)
        self.assertTrue(plugin_result.accepted_cipher_list)
        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        self.assertEquals({'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
                           'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
                           'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA256',
                           'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                           'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                           'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_RSA_WITH_AES_256_GCM_SHA384',
                           'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA256'},
                          set(accepted_cipher_name_list))

        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
