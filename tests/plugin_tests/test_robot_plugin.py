# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from tls_parser.tls_version import TlsVersionEnum

from sslyze.plugins.robot_plugin import RobotPlugin, RobotScanCommand, RobotScanResultEnum, RobotPmsPaddingPayloadEnum, \
    RobotTlsRecordPayloads
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.server_connectivity_tester import ServerConnectivityTester
from tests.travis_utils import IS_RUNNING_ON_TRAVIS


class RobotPluginPluginTestCase(unittest.TestCase):

    def test_robot_attack_good(self):
        # Validate the bug fix for https://github.com/nabla-c0d3/sslyze/issues/282
        server_test = ServerConnectivityTester(hostname='guide.duo.com')
        server_info = server_test.perform()

        plugin = RobotPlugin()
        plugin_result = plugin.process_task(server_info, RobotScanCommand())

        # On Travis CI we sometimes get inconsistent results
        if IS_RUNNING_ON_TRAVIS:
            self.assertIn(plugin_result.robot_result_enum, [RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE,
                                                            RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS])
        else:
            self.assertEqual(plugin_result.robot_result_enum, RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE)

        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_robot_attack_bad(self):
        # TODO(AD): Find a vulnerable server?
        pass
