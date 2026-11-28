import pytest
from nassl.ephemeral_key_info import OpenSslGroupNameEnum

from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
from sslyze.tls_config_checker.tls_config_checker import (
    ServerNotCompliantWithTlsConfiguration,
    ServerScanResultIncomplete,
    TlsConfiguration,
    TlsConfigurationEnum,
    check_server_against_tls_configuration,
)
from tests.factories import ServerScanResultFactory


# Use session as the scope so we only run this scan once through the test suite
@pytest.fixture(scope="session")
def server_scan_result_for_google():
    scanner = Scanner()
    scanner.queue_scans([ServerScanRequest(server_location=ServerNetworkLocation(hostname="google.com"))])
    yield from scanner.get_results()


class TestTlsConfigurationChecker:
    @pytest.mark.skip("Server needs to be updated; check https://github.com/chromium/badssl.com/issues/483")
    def test_badssl_compliant_with_intermediate(self):
        # Given the scan results for a server that is compliant with the TLSRef "intermediate" config
        scanner = Scanner()
        scanner.queue_scans(
            [ServerScanRequest(server_location=ServerNetworkLocation(hostname="mozilla-intermediate.badssl.com"))]
        )
        server_scan_result = next(scanner.get_results())

        # When checking if the server is compliant with the TLSRef "intermediate" TLS config
        # It succeeds and the server is returned as compliant
        tls_config = TlsConfiguration.get(TlsConfigurationEnum.INTERMEDIATE)
        check_server_against_tls_configuration(
            server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
        )

        # And the server is returned as NOT compliant for the other TLSRef configs
        for other_config in [TlsConfigurationEnum.MODERN]:
            tls_config = TlsConfiguration.get(other_config)
            with pytest.raises(ServerNotCompliantWithTlsConfiguration):
                check_server_against_tls_configuration(
                    server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
                )

    @pytest.mark.skip("Server needs to be updated; check https://github.com/chromium/badssl.com/issues/483")
    def test_badssl_compliant_with_modern(self):
        # Given the scan results for a server that is compliant with the TLSRef "modern" config
        scanner = Scanner()
        scanner.queue_scans(
            [ServerScanRequest(server_location=ServerNetworkLocation(hostname="mozilla-modern.badssl.com"))]
        )
        server_scan_result = next(scanner.get_results())

        # When checking if the server is compliant with the TLSRef "modern" TLS config
        # It succeeds and the server is returned as compliant
        tls_config = TlsConfiguration.get(TlsConfigurationEnum.MODERN)
        check_server_against_tls_configuration(
            server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
        )

        # And the server is returned as NOT compliant for the other TLSRef configs
        for other_config in [TlsConfigurationEnum.INTERMEDIATE]:
            tls_config = TlsConfiguration.get(other_config)
            with pytest.raises(ServerNotCompliantWithTlsConfiguration):
                check_server_against_tls_configuration(
                    server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
                )

    def test_multi_certs_deployment_not_compliant_with_intermediate(self, server_scan_result_for_google):
        # Give the scan results for google.com which has multiple leaf certificates
        # When checking if the server is compliant with the TLSRef "intermediate" TLS config
        tls_config = TlsConfiguration.get(TlsConfigurationEnum.INTERMEDIATE)

        # It succeeds and the server is returned as NOT compliant
        with pytest.raises(ServerNotCompliantWithTlsConfiguration):
            check_server_against_tls_configuration(
                server_scan_result=server_scan_result_for_google, tls_config_to_check_against=tls_config
            )

    def test_multi_certs_deployment_not_compliant_with_modern(self, server_scan_result_for_google):
        # Give the scan results for google.com which has multiple leaf certificates
        # When checking if the server is compliant with the TLSRef "modern" TLS config
        tls_config = TlsConfiguration.get(TlsConfigurationEnum.MODERN)

        # It succeeds and the server is returned as NOT compliant
        with pytest.raises(ServerNotCompliantWithTlsConfiguration):
            check_server_against_tls_configuration(
                server_scan_result=server_scan_result_for_google, tls_config_to_check_against=tls_config
            )

    @pytest.mark.parametrize(
        "tls_configuration_enum",
        [
            TlsConfigurationEnum.MODERN,
            TlsConfigurationEnum.INTERMEDIATE,
        ],
    )
    def test_tls_curves_use_the_group_names_returned_by_the_plugin(self, tls_configuration_enum):
        # Given a TLSRef TLS config
        tls_config = TlsConfiguration.get(tls_configuration_enum)

        # Then its TLS curves use the same names as the supported groups plugin, so that they can be compared
        assert tls_config.tls_curves <= {group for group in OpenSslGroupNameEnum}

    def test_intermediate_allows_x25519mlkem768(self):
        # Given the bundled "intermediate" TLS config
        tls_config = TlsConfiguration.get(TlsConfigurationEnum.INTERMEDIATE)

        # Then it allows X25519MLKEM768, so that servers that support it are not reported as non-compliant
        # https://github.com/nabla-c0d3/sslyze/issues/725
        assert OpenSslGroupNameEnum.X25519MLKEM768.value in tls_config.tls_curves

    def test_incomplete_scan_result(self):
        # Given a scan result that does not contain all the information needed by the TLS config checker
        server_scan_result = ServerScanResultFactory.create()

        # When checking the server is compliant
        tls_config = TlsConfiguration.get(TlsConfigurationEnum.MODERN)
        # It fails
        with pytest.raises(ServerScanResultIncomplete):
            check_server_against_tls_configuration(
                server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
            )
