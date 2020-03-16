import pytest

from sslyze.server_connectivity import ServerConnectivityTester, ClientAuthRequirementEnum
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum, LegacyOpenSslServer


class TestClientAuthentication:
    def test_optional_client_authentication(self):
        # Given a server that requires a client certificate
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname="client.badssl.com", port=443
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.cipher_suite_supported

        # And it detected the client authentication
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.OPTIONAL


@can_only_run_on_linux_64
class TestClientAuthenticationWithLocalServer:
    def test_optional_client_auth(self):
        # Given a server that supports optional client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.OPTIONAL) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, port=server.port, ip_address=server.ip_address
            )
            server_info = ServerConnectivityTester().perform(server_location)

        # SSLyze correctly detects that client auth is optional
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.OPTIONAL

    def test_required_client_auth_tls_1_2(self):
        # Given a TLS 1.2 server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, port=server.port, ip_address=server.ip_address
            )

            server_info = ServerConnectivityTester().perform(server_location)

        # SSLyze correctly detects that client auth is required
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.REQUIRED

    @pytest.mark.skip(msg="Client auth config detection with TLS 1.3 is broken; fix me")
    def test_required_client_auth_tls_1_3(self):
        # Given a TLS 1.3 server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, port=server.port, ip_address=server.ip_address
            )

            server_info = ServerConnectivityTester().perform(server_location)

        # SSLyze correctly detects that client auth is required
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.REQUIRED
