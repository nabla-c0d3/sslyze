from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanResult, FallbackScsvImplementation
from sslyze.server_connectivity import ServerConnectivityTester

from sslyze.server_setting import (
    ServerNetworkLocationViaDirectConnection,
    ServerNetworkConfiguration,
    ClientAuthenticationCredentials,
)
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum
import pytest


class TestFallbackScsvPlugin:
    def test_fallback_good(self):
        # Given a server that supports SCSV
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When testing for SCSV, it succeeds
        result: FallbackScsvScanResult = FallbackScsvImplementation.scan_server(server_info)

        # And the server is reported as supporting SCSV
        assert result.supports_fallback_scsv

        # And a CLI output can be generated
        assert FallbackScsvImplementation.cli_connector_cls.result_to_console_output(result)

    @can_only_run_on_linux_64
    def test_fallback_bad(self):
        # Given a server that does NOT support SCSV
        with LegacyOpenSslServer() as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for SCSV, it succeeds
            result: FallbackScsvScanResult = FallbackScsvImplementation.scan_server(server_info)

        # And the server is reported as NOT supporting SCSV
        assert not result.supports_fallback_scsv

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed(self):
        # Given a server that does NOT support SCSV and that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for SCSV, it fails as a client cert was not supplied
            with pytest.raises(ClientCertificateRequested):
                FallbackScsvImplementation.scan_server(server_info)

    @can_only_run_on_linux_64
    def test_works_when_client_auth_succeeded(self):
        # Given a server that does NOT support SCSV and that requires client authentication
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

            # When testing for SCSV, it succeeds
            result: FallbackScsvScanResult = FallbackScsvImplementation.scan_server(server_info)

        # And the server is reported as NOT supporting SCSV
        assert not result.supports_fallback_scsv
