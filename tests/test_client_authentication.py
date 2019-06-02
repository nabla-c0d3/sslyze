from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationServerConfigurationEnum
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum, LegacyOpenSslServer


class TestClientAuthentication:

    @can_only_run_on_linux_64
    def test_optional_client_auth(self):
        # Given a server that supports optional client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.OPTIONAL) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

        # SSLyze correctly detects that client auth is optional
        assert server_info.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.OPTIONAL

    @can_only_run_on_linux_64
    def test_required_client_auth_tls_1_2(self):
        # Given a TLS 1.2 server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

        # SSLyze correctly detects that client auth is required
        assert server_info.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.REQUIRED

    @can_only_run_on_linux_64
    def test_required_client_auth_tls_1_3(self):
        # Given a TLS 1.3 server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

        # SSLyze correctly detects that client auth is required
        # TODO(AD): Fix this bug; it should be REQUIRED
        assert server_info.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.OPTIONAL
