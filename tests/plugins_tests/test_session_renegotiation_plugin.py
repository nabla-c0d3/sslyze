from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.session_renegotiation_plugin import (
    SessionRenegotiationImplementation,
    SessionRenegotiationScanResult,
)
from sslyze.server_connectivity import ServerConnectivityTester

from sslyze.server_setting import (
    ServerNetworkLocationViaDirectConnection,
    ClientAuthenticationCredentials,
    ServerNetworkConfiguration,
)
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum
import pytest


class TestSessionRenegotiationPlugin:
    def test_renegotiation_good(self):
        # Given a server that is NOT vulnerable to insecure reneg
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When testing for insecure reneg, it succeeds
        result: SessionRenegotiationScanResult = SessionRenegotiationImplementation.scan_server(server_info)

        # And the server is reported as not vulnerable
        assert result.supports_secure_renegotiation
        assert not result.accepts_client_renegotiation

        # And a CLI output can be generated
        assert SessionRenegotiationImplementation.cli_connector_cls.result_to_console_output(result)

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed(self):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for insecure reneg, it fails
            with pytest.raises(ClientCertificateRequested):
                SessionRenegotiationImplementation.scan_server(server_info)

    @can_only_run_on_linux_64
    def test_works_when_client_auth_succeeded(self):
        # Given a server that is NOT vulnerable and that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            # And sslyze provides a client certificate
            network_config = ServerNetworkConfiguration(
                tls_server_name_indication=server.hostname,
                tls_client_auth_credentials=ClientAuthenticationCredentials(
                    certificate_chain_path=server.get_client_certificate_path(), key_path=server.get_client_key_path()
                ),
            )
            server_info = ServerConnectivityTester().perform(server_location, network_config)

            # When testing for insecure reneg, it succeeds
            result: SessionRenegotiationScanResult = SessionRenegotiationImplementation.scan_server(server_info)

            # And the server is reported as not vulnerable
            assert result.supports_secure_renegotiation
            assert result.accepts_client_renegotiation
