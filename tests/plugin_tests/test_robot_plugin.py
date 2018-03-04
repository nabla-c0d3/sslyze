# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import logging
import unittest

from nassl.ssl_client import ClientCertificateRequested
from tls_parser.tls_version import TlsVersionEnum

from sslyze.plugins.robot_plugin import RobotPlugin, RobotScanCommand, RobotScanResultEnum, RobotPmsPaddingPayloadEnum, \
    RobotTlsRecordPayloads
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationServerConfigurationEnum
from tests.openssl_server import VulnerableOpenSslServer, NotOnLinux64Error
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

    def test_fails_when_client_auth_failed(self):
        # Given a server that requires client authentication
        try:
            with VulnerableOpenSslServer(
                    client_auth_config=ClientAuthenticationServerConfigurationEnum.REQUIRED
            ) as server:
                # And the client does NOT provide a client certificate
                server_test = ServerConnectivityTester(
                    hostname=server.hostname,
                    ip_address=server.ip_address,
                    port=server.port
                )
                server_info = server_test.perform()

                # The plugin fails when a client cert was not supplied
                plugin = RobotPlugin()
                with self.assertRaises(ClientCertificateRequested):
                    plugin.process_task(server_info, RobotScanCommand())

        except NotOnLinux64Error:
            logging.warning('WARNING: Not on Linux - skipping test')
            return
