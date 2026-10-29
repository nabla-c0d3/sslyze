from nassl.ephemeral_key_info import OpenSslGroupNameEnum

from sslyze import ServerNetworkLocation
from sslyze.plugins.supported_groups_plugin import (
    SupportedGroupsImplementation,
    SupportedGroupsScanResult,
    SupportedGroupsScanResultAsJson,
)
from sslyze.server_connectivity import ClientAuthRequirementEnum, ServerTlsProbingResult, TlsVersionEnum
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.factories import ServerConnectivityInfoFactory
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ClientAuthConfigEnum, LegacyOpenSslServer, ModernOpenSslServer, S_Server_OpenSSL_4_0_0


class TestSupportedGroupsPluginWithOnlineServer:
    def test_full_support(self) -> None:
        # Given a server known to support TLS 1.3, ECDH cipher suites and PQ/hybrid key exchange
        server_location = ServerNetworkLocation("www.cloudflare.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for supported groups, it succeeds
        result: SupportedGroupsScanResult = SupportedGroupsImplementation.scan_server(server_info)

        # And the server is reported as supporting Elliptic Curve key exchange
        assert result.supports_elliptic_curve_key_exchange
        assert result.supported_elliptic_curve_groups
        assert result.rejected_elliptic_curve_groups is not None

        # And the server is reported as supporting Post-Quantum/hybrid key exchange
        assert result.supports_post_quantum_key_exchange
        assert result.supported_post_quantum_groups is not None
        assert OpenSslGroupNameEnum.X25519MLKEM768.value in result.supported_post_quantum_groups
        assert result.rejected_post_quantum_groups is not None

        # And Finite Field DH groups were tested as well
        assert result.supported_finite_field_dh_groups is not None
        assert result.rejected_finite_field_dh_groups is not None

        # And a CLI output can be generated
        cli_output = SupportedGroupsImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output
        assert any(OpenSslGroupNameEnum.X25519MLKEM768 in line for line in cli_output)

        # And the result can be converted to JSON
        result_as_json_str = SupportedGroupsScanResultAsJson.model_validate(result).model_dump_json()
        assert OpenSslGroupNameEnum.X25519MLKEM768 in result_as_json_str

    def test_ffdh_groups(self) -> None:
        # Given a server known to support Finite Field DH groups
        server_location = ServerNetworkLocation("www.free.fr", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for supported groups, it succeeds
        result: SupportedGroupsScanResult = SupportedGroupsImplementation.scan_server(server_info)

        # And the server is reported as supporting Finite Field DH groups
        assert result.supported_finite_field_dh_groups
        assert result.rejected_finite_field_dh_groups is not None

        # And a CLI output can be generated
        cli_output = SupportedGroupsImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output
        assert any(OpenSslGroupNameEnum.X25519MLKEM768 in line for line in cli_output)

        # And the result can be converted to JSON
        result_as_json_str = SupportedGroupsScanResultAsJson.model_validate(result).model_dump_json()
        assert OpenSslGroupNameEnum.X25519MLKEM768 in result_as_json_str


class TestSupportedGroupsPluginWithNoUsableTlsVersion:
    def test_nothing_to_test(self) -> None:
        # Given a server that does not support any usable TLS version
        server_info = ServerConnectivityInfoFactory.create(
            tls_probing_result=ServerTlsProbingResult(
                highest_tls_version_supported=TlsVersionEnum.SSL_3_0,
                cipher_suite_supported="AES",
                client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
                supports_ecdh_key_exchange=False,
            )
        )

        # When scanning for supported groups, no scan jobs are queued since there is nothing to test
        all_scan_jobs = SupportedGroupsImplementation.scan_jobs_for_scan_command(server_info)
        assert all_scan_jobs == []

        # And the result can still be generated, without making any network connection
        result = SupportedGroupsImplementation.result_for_completed_scan_jobs(server_info, [])

        # And the result reports that nothing could be tested
        assert result.supported_elliptic_curve_groups is None
        assert result.rejected_elliptic_curve_groups is None
        assert not result.supports_elliptic_curve_key_exchange

        assert result.supported_finite_field_dh_groups == []
        assert result.rejected_finite_field_dh_groups == []

        assert result.supported_post_quantum_groups is None
        assert result.rejected_post_quantum_groups is None
        assert not result.supports_post_quantum_key_exchange

        # And a CLI output can still be generated
        cli_output = SupportedGroupsImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output

        # And the result can be converted to JSON
        result_as_json = SupportedGroupsScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json


@can_only_run_on_linux_64
class TestSupportedGroupsPluginWithLocalServer:
    def test_specific_elliptic_curves_supported(self) -> None:
        # Given a server that only supports specific elliptic curves
        server_curves = ["X25519", "X448", "secp384r1", "secp521r1"]
        with ModernOpenSslServer(groups=":".join(server_curves)) as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When scanning for supported groups, it succeeds
            result: SupportedGroupsScanResult = SupportedGroupsImplementation.scan_server(server_info)

        # And exactly the configured curves were detected as supported, with their OpenSSL 4 group names
        assert result.supported_elliptic_curve_groups is not None
        assert {curve.lower() for curve in server_curves} == set(result.supported_elliptic_curve_groups)

    def test_brainpool_tls_1_3_groups_supported(self) -> None:
        # Given a TLS 1.3 server that supports the brainpool groups specific to TLS 1.3
        brainpool_tls_1_3_groups = [
            OpenSslGroupNameEnum.brainpoolP256r1tls13.value,
            OpenSslGroupNameEnum.brainpoolP384r1tls13.value,
            OpenSslGroupNameEnum.brainpoolP512r1tls13.value,
        ]
        # And x25519, so that the connectivity check succeeds
        with S_Server_OpenSSL_4_0_0(groups=":".join(["x25519", *brainpool_tls_1_3_groups])) as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When scanning for supported groups, it succeeds
            result: SupportedGroupsScanResult = SupportedGroupsImplementation.scan_server(server_info)

        # And the brainpool TLS 1.3 groups were detected as supported
        assert result.supported_elliptic_curve_groups is not None
        assert set(brainpool_tls_1_3_groups).issubset(result.supported_elliptic_curve_groups)

    def test_only_post_quantum_group_supported(self) -> None:
        # Given a server that only accepts a post-quantum/hybrid group, which the OpenSSL 1.1.1 client cannot offer
        with S_Server_OpenSSL_4_0_0(groups="X25519MLKEM768") as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )

            # When testing connectivity, it succeeds
            server_info = check_connectivity_to_server_and_return_info(server_location)
            assert server_info.tls_probing_result.highest_tls_version_supported == TlsVersionEnum.TLS_1_3

            # And when scanning for supported groups, it succeeds
            result: SupportedGroupsScanResult = SupportedGroupsImplementation.scan_server(server_info)

        # And only the post-quantum/hybrid group was detected as supported
        assert result.supported_post_quantum_groups == [OpenSslGroupNameEnum.X25519MLKEM768.value]
        assert not result.supported_elliptic_curve_groups
        assert not result.supported_finite_field_dh_groups

    def test_tls_1_3_not_supported(self) -> None:
        # Given a server that only supports up to TLS 1.2 (no TLS 1.3)
        with LegacyOpenSslServer() as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)
            assert server_info.tls_probing_result.highest_tls_version_supported.value < TlsVersionEnum.TLS_1_3.value

            # When scanning for supported groups, it succeeds
            result: SupportedGroupsScanResult = SupportedGroupsImplementation.scan_server(server_info)

        # And PQ/hybrid key exchange is reported as not applicable, since it requires TLS 1.3
        assert result.supported_post_quantum_groups is None
        assert result.rejected_post_quantum_groups is None
        assert not result.supports_post_quantum_key_exchange

        # But Elliptic Curve and Finite Field DH groups were still tested normally
        assert result.supported_elliptic_curve_groups is not None
        assert result.supports_elliptic_curve_key_exchange
        assert result.supported_finite_field_dh_groups is not None

        # And the CLI output explains why PQ/hybrid key exchange could not be tested
        cli_output = SupportedGroupsImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("TLS 1.3" in line for line in cli_output)

    def test_no_ecdh_cipher_suites_supported(self) -> None:
        # Given a server that only supports non-ECDHE cipher suites
        with LegacyOpenSslServer(openssl_cipher_string="AES128-SHA:AES256-SHA") as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)
            assert not server_info.tls_probing_result.supports_ecdh_key_exchange

            # When scanning for supported groups, it succeeds
            result: SupportedGroupsScanResult = SupportedGroupsImplementation.scan_server(server_info)

        # And Elliptic Curve key exchange is reported as not supported
        assert result.supported_elliptic_curve_groups is None
        assert result.rejected_elliptic_curve_groups is None
        assert not result.supports_elliptic_curve_key_exchange

        # But Finite Field DH groups were still tested normally
        assert result.supported_finite_field_dh_groups is not None

        # And the CLI output explains that ECDH is not supported
        cli_output = SupportedGroupsImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("ECDH" in line for line in cli_output)

    def test_client_certificate_requested(self) -> None:
        # Given a server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )

            # And sslyze does NOT provide a client certificate
            server_info = check_connectivity_to_server_and_return_info(server_location)
            assert server_info.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.REQUIRED

            # When scanning for supported groups, it still succeeds despite the missing client certificate
            result: SupportedGroupsScanResult = SupportedGroupsImplementation.scan_server(server_info)

        # And Elliptic Curve groups are still correctly detected: the key exchange completes before the server
        # asks for (and sslyze fails to provide) a client certificate
        assert result.supports_elliptic_curve_key_exchange
        assert result.supported_elliptic_curve_groups
        assert result.rejected_elliptic_curve_groups is not None

        # And a CLI output can be generated
        cli_output = SupportedGroupsImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output

        # And the result can be converted to JSON
        result_as_json = SupportedGroupsScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json
