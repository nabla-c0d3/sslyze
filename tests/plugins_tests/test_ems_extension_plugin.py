import pytest
from nassl.base_ssl_client import ClientCertificateRequested

from sslyze.plugins.ems_extension_plugin import (
    EmsExtensionImplementation,
    EmsExtensionScanResult,
    EmsExtensionScanResultAsJson,
)
from sslyze.server_setting import (
    ClientAuthenticationCredentials,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
)
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ClientAuthConfigEnum, LegacyOpenSslServer


class TestFallbackScsvPlugin:
    def test_good(self) -> None:
        # Given a server that supports Extended Master Secret
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When testing for EMS support, it succeeds with the expected result
        result: EmsExtensionScanResult = EmsExtensionImplementation.scan_server(server_info)
        assert result.supports_ems_extension

        # And a CLI output can be generated
        assert EmsExtensionImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = EmsExtensionScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    @can_only_run_on_linux_64
    def test_bad(self) -> None:
        # Given a server that does NOT support EMS
        with LegacyOpenSslServer() as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When testing for EMS, it succeeds
            result: EmsExtensionScanResult = EmsExtensionImplementation.scan_server(server_info)

        # And the server is reported as NOT supporting it
        assert not result.supports_ems_extension

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed(self) -> None:
        # Given a server that does NOT support EMS and that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When testing, it fails as a client cert was not supplied
            with pytest.raises(ClientCertificateRequested):
                EmsExtensionImplementation.scan_server(server_info)

    @can_only_run_on_linux_64
    def test_works_when_client_auth_succeeded(self) -> None:
        # Given a server that does NOT support EMS and that requires client authentication
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

            # When testing for EMS, it succeeds
            result: EmsExtensionScanResult = EmsExtensionImplementation.scan_server(server_info)

        # And the server is reported as NOT supporting EMS
        assert not result.supports_ems_extension
