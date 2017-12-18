# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest
from sslyze.plugins.robot_plugin import RobotPlugin, RobotScanCommand, RobotScanResultEnum
from sslyze.server_connectivity import ServerConnectivityInfo


class RobotPluginPluginTestCase(unittest.TestCase):

    def test_robot_attack_good(self):
        server_info = ServerConnectivityInfo(hostname='www.google.com')
        server_info.test_connectivity_to_server()

        plugin = RobotPlugin()
        plugin_result = plugin.process_task(server_info, RobotScanCommand())

        self.assertEqual(plugin_result.robot_result_enum, RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_robot_attack_bad(self):
        # TODO(AD): Find a vulnerable server?
        pass
