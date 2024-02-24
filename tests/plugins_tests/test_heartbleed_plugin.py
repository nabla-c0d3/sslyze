from sslyze.plugins.heartbleed_plugin import HeartbleedImplementation, HeartbleedScanResultAsJson
from sslyze.server_setting import ServerNetworkLocation
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.markers import can_only_run_on_linux_64

from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


class TestHeartbleedPlugin:
    def test_not_vulnerable(self):
        # Given a server that is NOT vulnerable to Heartbleed
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When testing for Heartbleed, it succeeds
        result = HeartbleedImplementation.scan_server(server_info)

        # And the server is reported as not vulnerable
        assert not result.is_vulnerable_to_heartbleed

        # And a CLI output can be generated
        assert HeartbleedImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = HeartbleedScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_not_vulnerable_and_server_has_cloudfront_bug(self):
        # Test for https://github.com/nabla-c0d3/sslyze/issues/437
        # Given a server that is NOT vulnerable to CCS injection and that is hosted on Cloudfront with the SNI bug
        server_location = ServerNetworkLocation(hostname="uol.com", port=443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When testing for CCS injection, it succeeds
        result = HeartbleedImplementation.scan_server(server_info)

        # And the server is reported as not vulnerable
        assert not result.is_vulnerable_to_heartbleed

    @can_only_run_on_linux_64
    def test_vulnerable(self):
        # Given a server that is vulnerable to Heartbleed
        with LegacyOpenSslServer() as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When testing for Heartbleed, it succeeds
            result = HeartbleedImplementation.scan_server(server_info)

        # And the server is reported as vulnerable
        assert result.is_vulnerable_to_heartbleed

        # And a CLI output can be generated
        assert HeartbleedImplementation.cli_connector_cls.result_to_console_output(result)

    @can_only_run_on_linux_64
    def test_vulnerable_and_server_has_sni_bug(self):
        # Test for https://github.com/nabla-c0d3/sslyze/issues/202
        # Given a server that is vulnerable to Heartbleed and that requires the right SNI to be sent
        server_name_indication = "server.com"
        with LegacyOpenSslServer(require_server_name_indication_value=server_name_indication) as server:
            server_location = ServerNetworkLocation(
                hostname=server_name_indication, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # But the server is buggy and returns a TLS alert when SNI is sent during the Hearbtleed check
            # We replicate this behavior by having SSLyze send a wrong value for SNI, instead of complicated server code
            # Use __setattr__ to bypass the dataclass' frozen=True setting
            object.__setattr__(server_info.network_configuration, "tls_server_name_indication", "wrongvalue.com")

            # When testing for Heartbleed, it succeeds
            result = HeartbleedImplementation.scan_server(server_info)

        # And the server is reported as vulnerable even though it has the SNI bug
        assert result.is_vulnerable_to_heartbleed

    @can_only_run_on_linux_64
    def test_succeeds_when_client_auth_failed(self):
        # Given a server that is vulnerable to Heartbleed and that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When testing for Heartbleed, it succeeds
            result = HeartbleedImplementation.scan_server(server_info)

        # And the server is reported as vulnerable
        assert result.is_vulnerable_to_heartbleed
