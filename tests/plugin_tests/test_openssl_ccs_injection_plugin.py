import os
import shlex
import unittest
from sys import platform

import logging

import subprocess

from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionPlugin, OpenSslCcsInjectionScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from tests.plugin_tests.openssl_server import VulnerableOpenSslServer, NotOnLinux64Error


class OpenSslCcsInjectionPluginTestCase(unittest.TestCase):

    def test_ccs_injection_good(self):
        server_info = ServerConnectivityInfo(hostname=u'www.google.com')
        server_info.test_connectivity_to_server()

        plugin = OpenSslCcsInjectionPlugin()
        plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())

        self.assertFalse(plugin_result.is_vulnerable_to_ccs_injection)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_ccs_injection_bad(self):
        try:
            server = VulnerableOpenSslServer(port=4001)
        except NotOnLinux64Error:
            # The test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits
            logging.warning('WARNING: Not on Linux - skipping OpenSSL CCS test')
            return

        server.start()
        server_info = ServerConnectivityInfo(hostname='localhost', ip_address='127.0.0.1',  port=4001)
        server_info.test_connectivity_to_server()

        plugin = OpenSslCcsInjectionPlugin()
        plugin_result = plugin.process_task(server_info, OpenSslCcsInjectionScanCommand())

        self.assertTrue(plugin_result.is_vulnerable_to_ccs_injection)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        server.terminate()
