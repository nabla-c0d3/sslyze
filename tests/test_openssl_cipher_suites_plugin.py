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

        # TODO: More specific check
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

        # TODO: More specific check
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

        # TODO: More specific check
        self.assertTrue(plugin_result.preferred_cipher)
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

        # TODO: More specific check
        self.assertTrue(plugin_result.preferred_cipher)
        self.assertTrue(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    def test_tlsv1_2_enabled(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, 'tlsv1_2')

        # TODO: More specific check
        self.assertTrue(plugin_result.preferred_cipher)
        self.assertTrue(plugin_result.accepted_cipher_list)
        self.assertTrue(plugin_result.rejected_cipher_list)
        self.assertFalse(plugin_result.errored_cipher_list)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
