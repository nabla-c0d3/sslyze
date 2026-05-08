from sslyze import ServerNetworkLocation
from sslyze.plugins.pq_key_exchange_plugin import (
    PqKeyExchangeImplementation,
    PqKeyExchangeScanResult,
    PqKeyExchangeScanResultAsJson,
    PqGroup,
)
from sslyze.server_connectivity import TlsVersionEnum
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.factories import ServerConnectivityInfoFactory, ServerTlsProbingResultFactory
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer


class TestPqKeyExchangePluginWithOnlineServer:
    def test_pq_groups_supported(self) -> None:
        # Given a server known to support PQ/hybrid key exchange (cloudflare.com supports X25519MLKEM768)
        server_location = ServerNetworkLocation("www.cloudflare.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for PQ group support, it succeeds
        result: PqKeyExchangeScanResult = PqKeyExchangeImplementation.scan_server(server_info)

        # And the server is reported as PQ-ready
        assert result.supports_pq_key_exchange
        assert result.supported_pq_groups is not None
        assert PqGroup.X25519MLKEM768.value in result.supported_pq_groups

        # And a CLI output can be generated
        cli_output = PqKeyExchangeImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output
        assert any(PqGroup.X25519MLKEM768.value in line for line in cli_output)

        # And the result can be converted to JSON and back
        result_as_json_str = PqKeyExchangeScanResultAsJson.model_validate(result).model_dump_json()
        assert PqGroup.X25519MLKEM768.value in result_as_json_str


class TestPqKeyExchangePluginTls13NotSupported:
    def test_tls13_not_supported(self) -> None:
        # Given a server that only supports TLS 1.2 (no TLS 1.3)
        server_info = ServerConnectivityInfoFactory.create(
            tls_probing_result=ServerTlsProbingResultFactory.create()  # defaults to TLS 1.2
        )
        assert server_info.tls_probing_result.highest_tls_version_supported == TlsVersionEnum.TLS_1_2

        # When scanning for PQ group support, it succeeds without making any network connection
        result: PqKeyExchangeScanResult = PqKeyExchangeImplementation.scan_server(server_info)

        # And the result reports PQ testing was not applicable
        assert result.supported_pq_groups is None
        assert not result.supports_pq_key_exchange

        # And the CLI output explains why TLS 1.3 is required
        cli_output = PqKeyExchangeImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output
        assert any("TLS 1.3" in line for line in cli_output)

        # And the result can be converted to JSON
        result_as_json_str = PqKeyExchangeScanResultAsJson.model_validate(result).model_dump_json()
        assert "null" in result_as_json_str  # supported_pq_groups is None


@can_only_run_on_linux_64
class TestPqKeyExchangePluginWithLocalServer:
    def test_no_pq_groups_accepted(self) -> None:
        # Given a local server (OpenSSL 1.1.1) that supports TLS 1.3 but no PQ/hybrid groups
        with ModernOpenSslServer(groups="X25519:P-256:P-384") as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When scanning for PQ group support, it succeeds
            result: PqKeyExchangeScanResult = PqKeyExchangeImplementation.scan_server(server_info)

        # And the server is reported as NOT PQ-ready (no hybrid groups accepted)
        assert not result.supports_pq_key_exchange
        assert result.supported_pq_groups == []

        # And the CLI output flags the absence as a finding
        cli_output = PqKeyExchangeImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output
        assert any("VULNERABLE" in line for line in cli_output)
