# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import unittest

import pickle

from nassl.ocsp_response import OcspResponseStatusEnum

from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin, CertificateInfoScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo


class CertificateInfoPluginTestCase(unittest.TestCase):

    def test_ca_file_bad_file(self):
        server_info = ServerConnectivityInfo(hostname='www.hotmail.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        with self.assertRaises(ValueError):
            plugin.process_task(server_info, CertificateInfoScanCommand(ca_file='doesntexist'))

    def test_ca_file(self):
        server_info = ServerConnectivityInfo(hostname='www.hotmail.com')
        server_info.test_connectivity_to_server()

        ca_file_path = os.path.join(os.path.dirname(__file__), '..', 'utils', 'wildcard-self-signed.pem')
        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand(ca_file=ca_file_path))

        self.assertEqual(len(plugin_result.path_validation_result_list), 6)
        for path_validation_result in plugin_result.path_validation_result_list:
            if path_validation_result.trust_store.name == 'Custom --ca_file':
                self.assertFalse(path_validation_result.is_certificate_trusted)
            else:
                self.assertTrue(path_validation_result.is_certificate_trusted)

    def test_valid_chain_with_ocsp_stapling_and_must_staple(self):
        server_info = ServerConnectivityInfo(hostname='www.scotthelme.co.uk')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertTrue(plugin_result.ocsp_response)
        self.assertEqual(plugin_result.ocsp_response_status, OcspResponseStatusEnum.SUCCESSFUL)
        self.assertTrue(plugin_result.is_ocsp_response_trusted)
        self.assertTrue(plugin_result.certificate_has_must_staple_extension)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_valid_chain_with_ev_cert(self):
        server_info = ServerConnectivityInfo(hostname='www.comodo.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertTrue(plugin_result.is_leaf_certificate_ev)

        self.assertEqual(len(plugin_result.certificate_chain), 3)
        self.assertEqual(len(plugin_result.verified_certificate_chain), 3)
        self.assertFalse(plugin_result.has_anchor_in_certificate_chain)

        self.assertEqual(len(plugin_result.path_validation_result_list), 5)
        for path_validation_result in plugin_result.path_validation_result_list:
            self.assertTrue(path_validation_result.is_certificate_trusted)

        self.assertEqual(len(plugin_result.path_validation_error_list), 0)
        self.assertEqual(plugin_result.certificate_matches_hostname, True)
        self.assertTrue(plugin_result.is_certificate_chain_order_valid)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_invalid_chain(self):
        server_info = ServerConnectivityInfo(hostname='self-signed.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertIsNone(plugin_result.ocsp_response)
        self.assertEqual(len(plugin_result.certificate_chain), 1)

        self.assertEqual(len(plugin_result.path_validation_result_list), 5)
        for path_validation_result in plugin_result.path_validation_result_list:
            self.assertFalse(path_validation_result.is_certificate_trusted)

        self.assertEqual(plugin_result.certificate_included_scts_count, 0)

        self.assertEqual(len(plugin_result.path_validation_error_list), 0)
        self.assertEqual(plugin_result.certificate_matches_hostname, True)
        self.assertTrue(plugin_result.is_certificate_chain_order_valid)
        self.assertIsNone(plugin_result.has_anchor_in_certificate_chain)
        self.assertIsNone(plugin_result.has_sha1_in_certificate_chain)
        self.assertFalse(plugin_result.verified_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_1000_sans_chain(self):
        # Ensure SSLyze can process a leaf cert with 1000 SANs
        server_info = ServerConnectivityInfo(hostname='1000-sans.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin.process_task(server_info, CertificateInfoScanCommand())

    def test_sha1_chain(self):
        server_info = ServerConnectivityInfo(hostname='sha1-intermediate.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertTrue(plugin_result.has_sha1_in_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_sha256_chain(self):
        server_info = ServerConnectivityInfo(hostname='sha256.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertFalse(plugin_result.has_sha1_in_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_unicode_certificate(self):
        server_info = ServerConnectivityInfo(hostname='เพย์สบาย.th')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertGreaterEqual(len(plugin_result.certificate_chain), 1)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_ecdsa_certificate(self):
        server_info = ServerConnectivityInfo(hostname='www.cloudflare.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertGreaterEqual(len(plugin_result.certificate_chain), 1)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_chain_with_anchor(self):
        server_info = ServerConnectivityInfo(hostname='www.verizon.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertTrue(plugin_result.has_anchor_in_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_not_trusted_by_mozilla_but_trusted_by_microsoft(self):
        server_info = ServerConnectivityInfo(hostname='webmail.russia.nasa.gov')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertEqual(plugin_result.successful_trust_store.name, 'Windows')

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_only_trusted_by_custom_ca_file(self):
        server_info = ServerConnectivityInfo(hostname='self-signed.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        ca_file_path = os.path.join(os.path.dirname(__file__), '..', 'utils', 'self-signed.badssl.com.pem')
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand(ca_file=ca_file_path))

        self.assertEqual(plugin_result.successful_trust_store.name, 'Custom --ca_file')
        self.assertTrue(plugin_result.verified_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_certificate_with_no_cn(self):
        server_info = ServerConnectivityInfo(hostname='no-common-name.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertTrue(plugin_result.verified_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_certificate_with_no_subject(self):
        server_info = ServerConnectivityInfo(hostname='no-subject.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertTrue(plugin_result.verified_certificate_chain)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_certificate_with_scts(self):
        server_info = ServerConnectivityInfo(hostname='www.apple.com')
        server_info.test_connectivity_to_server()

        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())

        self.assertEqual(plugin_result.certificate_included_scts_count, 3)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))
