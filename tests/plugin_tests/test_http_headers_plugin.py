# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from tests import SslyzeTestCase
import pickle
from sslyze.plugins.http_headers_plugin import HttpHeadersPlugin, HttpHeadersScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo


class HttpHeadersPluginTestCase(SslyzeTestCase):

    def test_hsts_enabled(self):
        server_info = ServerConnectivityInfo(hostname='hsts.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        self.assertTrue(plugin_result.hsts_header)
        self.assertFalse(plugin_result.hpkp_header)
        self.assertIsNone(plugin_result.is_valid_pin_configured)
        self.assertIsNone(plugin_result.is_backup_pin_configured)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_hsts_and_hpkp_disabled(self):
        server_info = ServerConnectivityInfo(hostname='expired.badssl.com')
        server_info.test_connectivity_to_server()

        plugin = HttpHeadersPlugin()
        plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

        self.assertFalse(plugin_result.hsts_header)
        self.assertFalse(plugin_result.hpkp_header)
        self.assertIsNone(plugin_result.is_valid_pin_configured)
        self.assertIsNone(plugin_result.is_backup_pin_configured)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_hpkp_enabled(self):
        # HPKP is being deprecated in Chrome - I couldn't find a website with the header set
        pass

    def test_expect_ct_disabled(self):
      server_info = ServerConnectivityInfo(hostname='hsts.badssl.com')
      server_info.test_connectivity_to_server()

      plugin = HttpHeadersPlugin()
      plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

      self.assertFalse(plugin_result.expect_ct_header)

      self.assertTrue(plugin_result.as_text())
      self.assertTrue(plugin_result.as_xml())

      self.assertTrue(pickle.dumps(plugin_result))

    def test_expect_ct_enabled(self):
      # Github was the only server I could find with expect-ct header set
      server_info = ServerConnectivityInfo(hostname='github.com')
      server_info.test_connectivity_to_server()

      plugin = HttpHeadersPlugin()
      plugin_result = plugin.process_task(server_info, HttpHeadersScanCommand())

      self.assertTrue(plugin_result.expect_ct_header)
      self.assertTrue(plugin_result.expect_ct_header.max_age >= 0)

      self.assertTrue(plugin_result.as_text())
      self.assertTrue(plugin_result.as_xml())

      self.assertTrue(pickle.dumps(plugin_result))
