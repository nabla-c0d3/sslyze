import pytest
from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.http_headers_plugin import HttpHeadersImplementation, HttpHeadersScanResult
from sslyze.server_connectivity import ServerConnectivityTester

from sslyze.server_setting import (
    ServerNetworkLocationViaDirectConnection,
    ServerNetworkConfiguration,
    ClientAuthenticationCredentials,
)
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ClientAuthConfigEnum, LegacyOpenSslServer


class TestHttpHeadersPlugin:
    def test_hsts_enabled(self):
        # Given a server to scan that has HSTS enabled
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("hsts.badssl.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for HTTP headers, it succeeds
        result: HttpHeadersScanResult = HttpHeadersImplementation.perform(server_info)

        # And only HSTS is detected
        assert result.strict_transport_security_header
        assert not result.public_key_pins_header
        assert not result.public_key_pins_report_only_header
        assert not result.expect_ct_header

    def test_hsts_and_hpkp_disabled(self):
        # Given a server to scan that does not have security headers
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("expired.badssl.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for HTTP headers, it succeeds
        result: HttpHeadersScanResult = HttpHeadersImplementation.perform(server_info)

        # And no headers are detected
        assert not result.strict_transport_security_header
        assert not result.public_key_pins_header
        assert not result.public_key_pins_report_only_header
        assert not result.expect_ct_header

    def test_expect_ct_enabled(self):
        # Given a server to scan that has Expect-CT enabled
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("github.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for HTTP headers, it succeeds
        result: HttpHeadersScanResult = HttpHeadersImplementation.perform(server_info)

        # And the Expect-CT header was detected
        assert result.expect_ct_header
        assert result.expect_ct_header.max_age >= 0

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed(self):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When scanning for HTTP headers, it fails
            with pytest.raises(ClientCertificateRequested):
                HttpHeadersImplementation.perform(server_info)

    @can_only_run_on_linux_64
    def test_works_when_client_auth_succeeded(self):
        # Given a server that requires client authentication
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

            # When scanning for HTTP headers, it succeeds
            result: HttpHeadersScanResult = HttpHeadersImplementation.perform(server_info)

            assert not result.strict_transport_security_header
            assert not result.public_key_pins_header
            assert not result.public_key_pins_report_only_header
            assert not result.expect_ct_header
