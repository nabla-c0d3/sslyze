from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.robot.implementation import RobotImplementation, RobotScanResult
from sslyze.plugins.robot._robot_tester import RobotScanResultEnum
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ClientAuthConfigEnum, LegacyOpenSslServer
import pytest


class TestRobotPluginPlugin:
    def test_robot_attack_good(self):
        # Validate the bug fix for https://github.com/nabla-c0d3/sslyze/issues/282
        # Given a server to scan that is not vulnerable to ROBOT
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("guide.duo.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        result: RobotScanResult = RobotImplementation.scan_server(server_info)
        assert result.robot_result == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE

        # And a CLI output can be generated
        assert RobotImplementation.cli_connector_cls.result_to_console_output(result)

    @pytest.mark.skip("Not implemented; TODO: Find a vulnerable server.")
    def test_robot_attack_bad(self):
        pass

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed(self):
        # Given a TLS 1.2 server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # The plugin fails
            with pytest.raises(ClientCertificateRequested):
                RobotImplementation.scan_server(server_info)
