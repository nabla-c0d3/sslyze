from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.robot_plugin import RobotPlugin, RobotScanCommand, RobotScanResultEnum
from sslyze.server_connectivity_tester import ServerConnectivityTester
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum, LegacyOpenSslServer
from tests.travis_utils import IS_RUNNING_ON_TRAVIS
import pytest


class TestRobotPluginPlugin:

    def test_robot_attack_good(self):
        # Validate the bug fix for https://github.com/nabla-c0d3/sslyze/issues/282
        server_test = ServerConnectivityTester(hostname='guide.duo.com')
        server_info = server_test.perform()

        plugin = RobotPlugin()
        plugin_result = plugin.process_task(server_info, RobotScanCommand())

        # On Travis CI we sometimes get inconsistent results
        if IS_RUNNING_ON_TRAVIS:
            assert plugin_result.robot_result_enum in [RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE,
                                                            RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS]
        else:
            assert plugin_result.robot_result_enum == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

    @pytest.mark.skip('Not implemented')
    def test_robot_attack_bad(self):
        # TODO(AD): Find a vulnerable server?
        pass

    @can_only_run_on_linux_64
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
            with pytest.raises(ClientCertificateRequested):
                plugin.process_task(server_info, RobotScanCommand())
