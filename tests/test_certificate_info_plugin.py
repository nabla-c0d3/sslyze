import unittest

from nassl import X509_NAME_MATCHES_SAN
from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError


class CertificateInfoPluginTestCase(unittest.TestCase):


    def test_invalid_chain(self):
        try:
            # First we must ensure that the server is reachable
            server_info = ServerConnectivityInfo(hostname='untrusted-root.badssl.com')
            server_info.test_connectivity_to_server()
        except ServerConnectivityError as e:
            raise RuntimeError('Error when connecting to {}: {}'.format(hostname, e.error_msg))

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertIsNone(plugin_result.ocsp_response)
        self.assertEquals(len(plugin_result.certificate_chain), 1)

        self.assertEquals(len(plugin_result.path_validation_result_list), 5)
        for path_validation_result in plugin_result.path_validation_result_list:
            self.assertFalse(path_validation_result.is_certificate_trusted)


        self.assertEquals(len(plugin_result.path_validation_error_list), 0)
        self.assertEquals(plugin_result.hostname_validation_result, X509_NAME_MATCHES_SAN)
        self.assertTrue(plugin_result.is_certificate_chain_order_valid)


        # TODO: Pass the untrusted root to ca_store and ensure it is valid