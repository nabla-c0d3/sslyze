# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

import pickle

from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationPlugin, SessionRenegotiationScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo


class SessionRenegotiationPluginTestCase(unittest.TestCase):

    def test_renegotiation_good(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = SessionRenegotiationPlugin()
        plugin_result = plugin.process_task(server_info, SessionRenegotiationScanCommand())

        self.assertFalse(plugin_result.accepts_client_renegotiation)
        self.assertTrue(plugin_result.supports_secure_renegotiation)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        self.assertTrue(pickle.dumps(plugin_result))

    def test_renegotiation_bad(self):
        # TBD
        pass