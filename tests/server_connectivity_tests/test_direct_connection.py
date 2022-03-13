import socket

import pytest

from sslyze.json.json_output import _ServerTlsProbingResultAsJson
from tests.openssl_server import LegacyOpenSslServer

from sslyze.server_connectivity import TlsVersionEnum, check_connectivity_to_server
from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration
from sslyze.errors import (
    ConnectionToServerTimedOut,
    ServerRejectedConnection,
    ServerTlsConfigurationNotSupported,
    ConnectionToServerFailed,
)
from tests.markers import can_only_run_on_linux_64


def _is_ipv6_available() -> bool:
    has_ipv6 = False
    s = socket.socket(socket.AF_INET6)
    try:
        s.connect(("2607:f8b0:4005:804::2004", 443))
        has_ipv6 = True
    except Exception:
        pass
    finally:
        s.close()
    return has_ipv6


class TestServerConnectivityTester:
    def test_via_direct_connection(self):
        # Given a server location
        server_location = ServerNetworkLocation("www.google.com", 443)

        # When testing connectivity
        tls_probing_result = check_connectivity_to_server(
            server_location=server_location,
            network_configuration=ServerNetworkConfiguration.default_for_server_location(server_location),
        )

        # It succeeds
        assert tls_probing_result.cipher_suite_supported
        assert tls_probing_result.highest_tls_version_supported
        assert tls_probing_result.client_auth_requirement
        assert tls_probing_result.supports_ecdh_key_exchange

        # And the result can be converted to JSON
        tls_probing_result_as_json = _ServerTlsProbingResultAsJson.from_orm(tls_probing_result)
        assert tls_probing_result_as_json.json()

    def test_via_direct_connection_but_server_timed_out(self):
        # Given a server location for a server that's offline
        server_location = ServerNetworkLocation(
            hostname="notarealdomain.not.real.notreal.not", port=1234, ip_address="123.123.123.123"
        )

        # When testing connectivity, it fails with the right error
        with pytest.raises(ConnectionToServerTimedOut):
            check_connectivity_to_server(
                server_location=server_location,
                network_configuration=ServerNetworkConfiguration.default_for_server_location(server_location),
            )

    def test_via_direct_connection_but_server_rejected_connection(self):
        # Given a server location for a server that's offline
        server_location = ServerNetworkLocation(hostname="localhost", port=1234)

        # When testing connectivity, it fails with the right error
        with pytest.raises(ServerRejectedConnection):
            check_connectivity_to_server(
                server_location=server_location,
                network_configuration=ServerNetworkConfiguration.default_for_server_location(server_location),
            )

    def test_via_direct_connection_but_server_tls_config_not_supported(self):
        # Given a server location for a server that only supports DH settings that SSLyze can't use
        server_location = ServerNetworkLocation(hostname="dh480.badssl.com", port=443)

        # When testing connectivity, it fails with the right error
        with pytest.raises(ServerTlsConfigurationNotSupported):
            check_connectivity_to_server(
                server_location=server_location,
                network_configuration=ServerNetworkConfiguration.default_for_server_location(server_location),
            )

    def test_tls_1_only(self):
        # Given a server that only supports TLS 1.0
        server_location = ServerNetworkLocation(hostname="tls-v1-0.badssl.com", port=1010)

        # When testing connectivity against it
        tls_probing_result = check_connectivity_to_server(
            server_location=server_location,
            network_configuration=ServerNetworkConfiguration.default_for_server_location(server_location),
        )

        # It succeeds
        assert tls_probing_result
        assert tls_probing_result.client_auth_requirement
        assert tls_probing_result.cipher_suite_supported

        # And it detected that only TLS 1.0 is supported
        assert tls_probing_result.highest_tls_version_supported == TlsVersionEnum.TLS_1_0

    @pytest.mark.skipif(not _is_ipv6_available(), reason="IPv6 not available")
    def test_ipv6(self):
        # Given a server accessible via IPv6
        server_location = ServerNetworkLocation(
            hostname="www.google.com", port=443, ip_address="2607:f8b0:4005:804::2004"
        )

        # When testing connectivity against it
        tls_probing_result = check_connectivity_to_server(
            server_location=server_location,
            network_configuration=ServerNetworkConfiguration.default_for_server_location(server_location),
        )

        # It succeeds
        assert tls_probing_result
        assert tls_probing_result.client_auth_requirement
        assert tls_probing_result.highest_tls_version_supported
        assert tls_probing_result.cipher_suite_supported

    def test_international_hostname(self):
        # Given a server with non-ascii characters in its hostname
        server_location = ServerNetworkLocation(hostname="www.société.com", port=443)

        # When testing connectivity against it
        tls_probing_result = check_connectivity_to_server(
            server_location=server_location,
            network_configuration=ServerNetworkConfiguration.default_for_server_location(server_location),
        )

        # It succeeds
        assert tls_probing_result
        assert tls_probing_result.client_auth_requirement
        assert tls_probing_result.highest_tls_version_supported
        assert tls_probing_result.cipher_suite_supported

        # And the result can be converted to JSON
        tls_probing_result_as_json = _ServerTlsProbingResultAsJson.from_orm(tls_probing_result)
        assert tls_probing_result_as_json.json()

    @can_only_run_on_linux_64
    def test_server_triggers_unexpected_connection_error(self):
        # Test for https://github.com/nabla-c0d3/sslyze/issues/430
        # Given a server that will trigger an unexpected / non-normal error during connectivity testing
        with LegacyOpenSslServer(
            # We test this behavior using the following error: the server requires the right SNI to be sent...
            require_server_name_indication_value="server.com"
        ) as server:
            server_location = ServerNetworkLocation(
                # ... but SSLyze will send a different value for SNI
                hostname="not_the_right_value.com",
                ip_address=server.ip_address,
                port=server.port,
            )

            # When testing connectivity against it
            # It fails and return the generic "connection failed" error, instead of crashing
            with pytest.raises(ConnectionToServerFailed) as e:
                check_connectivity_to_server(
                    server_location=server_location,
                    network_configuration=ServerNetworkConfiguration.default_for_server_location(server_location),
                )
                # And the actual error / root cause is mentioned in the message
                assert "unrecognized name" in e.error_message
