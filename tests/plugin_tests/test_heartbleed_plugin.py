import os
import shlex
import unittest

import logging
import subprocess

from sslyze.plugins.heartbleed_plugin import HeartbleedPlugin, HeartbleedScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from sys import platform

from tests.plugin_tests.openssl_server import NotOnLinux64Error
from tests.plugin_tests.openssl_server import VulnerableOpenSslServer


class HeartbleedPluginTestCase(unittest.TestCase):

    def test_heartbleed_good(self):
        server_info = ServerConnectivityInfo(hostname=u'www.google.com')
        server_info.test_connectivity_to_server()

        plugin = HeartbleedPlugin()
        plugin_result = plugin.process_task(server_info, HeartbleedScanCommand())

        self.assertFalse(plugin_result.is_vulnerable_to_heartbleed)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_heartbleed_bad(self):
        try:
            VulnerableOpenSslServer.start()
        except NotOnLinux64Error:
            # The test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits
            logging.warning('WARNING: Not on Linux - skipping Heartbleed test')
            return

        server_info = ServerConnectivityInfo(hostname=u'localhost', port=4433)
        server_info.test_connectivity_to_server()

        plugin = HeartbleedPlugin()
        plugin_result = plugin.process_task(server_info, HeartbleedScanCommand())

        self.assertTrue(plugin_result.is_vulnerable_to_heartbleed)
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        VulnerableOpenSslServer.terminate()
