# -*- coding: utf-8 -*-
import os
import unittest

from nassl import X509_NAME_MATCHES_SAN
from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
from sslyze.server_connectivity import ServerConnectivityInfo


class CertificateInfoPluginTestCase(unittest.TestCase):


    def test_valid_chain(self):
        server_info = ServerConnectivityInfo(hostname=u'www.hotmail.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertTrue(plugin_result.ocsp_response)
        self.assertTrue(plugin_result.is_ocsp_response_trusted)
        self.assertTrue(plugin_result.is_leaf_certificate_ev)

        self.assertEquals(len(plugin_result.certificate_chain), 2)
        self.assertEquals(len(plugin_result.verified_certificate_chain), 3)
        self.assertFalse(plugin_result.has_anchor_in_certificate_chain)

        self.assertEquals(len(plugin_result.path_validation_result_list), 5)
        for path_validation_result in plugin_result.path_validation_result_list:
            self.assertTrue(path_validation_result.is_certificate_trusted)

        self.assertEquals(len(plugin_result.path_validation_error_list), 0)
        self.assertEquals(plugin_result.hostname_validation_result, X509_NAME_MATCHES_SAN)
        self.assertTrue(plugin_result.is_certificate_chain_order_valid)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Test the --ca_path option
        plugin_result = plugin.process_task(server_info, 'certinfo_basic',
                                            {'ca_file': os.path.join(os.path.dirname(__file__), 'utils',
                                                                     'wildcard-self-signed.pem')})

        self.assertEquals(len(plugin_result.path_validation_result_list), 5)
        for path_validation_result in plugin_result.path_validation_result_list:
            if path_validation_result.trust_store.name == 'Custom --ca_file':
                self.assertFalse(path_validation_result.is_certificate_trusted)
            else:
                self.assertTrue(path_validation_result.is_certificate_trusted)


    def test_invalid_chain(self):
        server_info = ServerConnectivityInfo(hostname=u'self-signed.badssl.com')
        server_info.test_connectivity_to_server()

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
        self.assertIsNone(plugin_result.has_anchor_in_certificate_chain)
        self.assertIsNone(plugin_result.has_sha1_in_certificate_chain)
        self.assertFalse(plugin_result.verified_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    def test_1000_sans_chain(self):
        # Ensure SSLyze can process a leaf cert with 1000 SANs
        server_info = ServerConnectivityInfo(hostname=u'1000-sans.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        san_list = plugin_result.certificate_chain[0].as_dict['extensions']['X509v3 Subject Alternative Name']['DNS']
        self.assertEquals(len(san_list), 1000)


    def test_sha1_chain(self):
        server_info = ServerConnectivityInfo(hostname=u'sha1-2017.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertTrue(plugin_result.has_sha1_in_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    def test_sha256_chain(self):
        server_info = ServerConnectivityInfo(hostname=u'sha256.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertFalse(plugin_result.has_sha1_in_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    def test_unicode_certificate(self):
        server_info = ServerConnectivityInfo(hostname=u'www.főgáz.hu')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertTrue(plugin_result.certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())


    def test_chain_with_anchor(self):
        server_info = ServerConnectivityInfo(hostname=u'www.verizon.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, 'certinfo_basic')

        self.assertTrue(plugin_result.has_anchor_in_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())
