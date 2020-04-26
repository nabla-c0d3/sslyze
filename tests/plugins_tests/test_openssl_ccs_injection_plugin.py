from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionImplementation
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


class TestOpenSslCcsInjectionPlugin:
    def test_ccs_injection_good(self):
        # Given a server that is NOT vulnerable to CCS injection
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When testing for CCS injection, it succeeds
        result = OpenSslCcsInjectionImplementation.scan_server(server_info)

        # And the server is reported as not vulnerable
        assert not result.is_vulnerable_to_ccs_injection

        # And a CLI output can be generated
        assert OpenSslCcsInjectionImplementation.cli_connector_cls.result_to_console_output(result)

    @can_only_run_on_linux_64
    def test_ccs_injection_bad(self):
        # Given a server that is vulnerable to CCS injection
        with LegacyOpenSslServer() as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for CCS injection, it succeeds
            result = OpenSslCcsInjectionImplementation.scan_server(server_info)

        # And the server is reported as vulnerable
        assert result.is_vulnerable_to_ccs_injection

        # And a CLI output can be generated
        assert OpenSslCcsInjectionImplementation.cli_connector_cls.result_to_console_output(result)

    @can_only_run_on_linux_64
    def test_ccs_injection_bad_and_server_has_sni_bug(self):
        # Test for https://github.com/nabla-c0d3/sslyze/issues/202
        # Given a server that is vulnerable to CCS injection and that requires the right SNI to be sent
        server_name_indication = "server.com"
        with LegacyOpenSslServer(require_server_name_indication_value=server_name_indication) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server_name_indication, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # But the server is buggy and returns a TLS alert when SNI is sent during the CCS injection check
            # We replicate this behavior by having SSLyze send a wrong value for SNI, instead of complicated server code
            # Use __setattr__ to bypass the dataclass' frozen=True setting
            object.__setattr__(server_info.network_configuration, "tls_server_name_indication", "wrongvalue.com")

            # When testing for CCS injection, it succeeds
            result = OpenSslCcsInjectionImplementation.scan_server(server_info)

        # And the server is reported as vulnerable even though it has the SNI bug
        assert result.is_vulnerable_to_ccs_injection

    @can_only_run_on_linux_64
    def test_succeeds_when_client_auth_failed(self):
        # Given a server that is vulnerable to CCS injection and that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does not provide a client certificate
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When testing for CCS injection, it succeeds
            result = OpenSslCcsInjectionImplementation.scan_server(server_info)

        # And the server is reported as vulnerable
        assert result.is_vulnerable_to_ccs_injection
