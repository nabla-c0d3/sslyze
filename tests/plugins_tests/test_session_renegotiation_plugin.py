from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.session_renegotiation_plugin import (
    SessionRenegotiationImplementation,
    SessionRenegotiationScanResult,
    SessionRenegotiationScanResultAsJson,
)

from sslyze.server_setting import (
    ServerNetworkLocation,
    ClientAuthenticationCredentials,
    ServerNetworkConfiguration,
)
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum
import pytest


class TestSessionRenegotiationPlugin:
    def test_renegotiation_good(self) -> None:
        # Given a server that is NOT vulnerable to insecure reneg nor client reneg DOS
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When testing for insecure reneg, it succeeds
        result: SessionRenegotiationScanResult = SessionRenegotiationImplementation.scan_server(server_info)

        # And the server is reported as not vulnerable
        assert result.supports_secure_renegotiation
        assert not result.is_vulnerable_to_client_renegotiation_dos

        # And a CLI output can be generated
        assert SessionRenegotiationImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = SessionRenegotiationScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    @can_only_run_on_linux_64
    def test_renegotiation_is_vulnerable_to_client_renegotiation_dos(self) -> None:
        # Given a server that is vulnerable to client renegotiation DOS
        with LegacyOpenSslServer() as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When testing for insecure reneg, it succeeds
            result: SessionRenegotiationScanResult = SessionRenegotiationImplementation.scan_server(server_info)

        # And the server is reported as vulnerable
        assert result.is_vulnerable_to_client_renegotiation_dos

        # And a CLI output can be generated
        assert SessionRenegotiationImplementation.cli_connector_cls.result_to_console_output(result)

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed(self) -> None:
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When testing for insecure reneg, it fails
            with pytest.raises(ClientCertificateRequested):
                SessionRenegotiationImplementation.scan_server(server_info)

    @can_only_run_on_linux_64
    def test_works_when_client_auth_succeeded(self) -> None:
        # Given a server that is vulnerable and that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            # And sslyze provides a client certificate
            network_config = ServerNetworkConfiguration(
                tls_server_name_indication=server.hostname,
                tls_client_auth_credentials=ClientAuthenticationCredentials(
                    certificate_chain_path=server.get_client_certificate_path(), key_path=server.get_client_key_path()
                ),
            )
            server_info = check_connectivity_to_server_and_return_info(server_location, network_config)

            # When testing for insecure reneg, it succeeds
            result: SessionRenegotiationScanResult = SessionRenegotiationImplementation.scan_server(server_info)

            # And the results are correct
            assert result.supports_secure_renegotiation
            assert result.is_vulnerable_to_client_renegotiation_dos
