import pytest

from sslyze.plugins.compression_plugin import (
    CompressionImplementation,
    CompressionScanResult,
    CompressionScanResultAsJson,
)
from sslyze.server_setting import ServerNetworkLocation
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


class TestCompressionPlugin:
    def test_compression_disabled(self) -> None:
        # Given a server to scan that has TLS compression disabled
        server_location = ServerNetworkLocation(hostname="www.google.com", port=443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When testing for compression support, it succeeds
        result: CompressionScanResult = CompressionImplementation.scan_server(server_info)

        # And the right result is returned
        assert not result.supports_compression

        # And a CLI output can be generated
        assert CompressionImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CompressionScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    @pytest.mark.skip("Not implemented; find a server vulnerable to TLS compression")
    def test_compression_enabled(self) -> None:
        # TODO
        pass

    @can_only_run_on_linux_64
    def test_succeeds_when_client_auth_failed(self) -> None:
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When testing for compression support, it succeeds
            result: CompressionScanResult = CompressionImplementation.scan_server(server_info)

        assert not result.supports_compression
