import unittest

from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.robot_plugin import RobotPlugin, RobotScanCommand, RobotScanResultEnum
from sslyze.server_connectivity_tester import ServerConnectivityTester
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum, LegacyOpenSslServer
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

    @unittest.skip('Not implemented')
    def test_robot_attack_bad(self):
        # TODO(AD): Find a vulnerable server?
        pass

    @unittest.skipIf(not ModernOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_fails_when_client_auth_failed(self):
        # Given a TLS 1.2 server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
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
