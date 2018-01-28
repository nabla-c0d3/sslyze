# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from tests import SslyzeTestCase

from sslyze.concurrent_scanner import ConcurrentScanner
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.compression_plugin import CompressionScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.synchronous_scanner import SynchronousScanner


class ScannerTestCase(SslyzeTestCase):

    def test_synchronous_scanner(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        sync_scanner = SynchronousScanner()
        plugin_result = sync_scanner.run_scan_command(server_info, CompressionScanCommand())
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_concurrent_scanner(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        # Queue some scan commands that are quick
        concurrent_scanner = ConcurrentScanner()
        concurrent_scanner.queue_scan_command(server_info, CertificateInfoScanCommand())
        concurrent_scanner.queue_scan_command(server_info, SessionRenegotiationScanCommand())
        concurrent_scanner.queue_scan_command(server_info, CompressionScanCommand())

        # Process the results
        nb_results = 0
        for plugin_result in concurrent_scanner.get_results():
            self.assertTrue(plugin_result.as_text())
            self.assertTrue(plugin_result.as_xml())
            nb_results +=1

        self.assertEqual(nb_results, 3)
