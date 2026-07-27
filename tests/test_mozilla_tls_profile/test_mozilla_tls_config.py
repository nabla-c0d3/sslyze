import pytest

from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
from sslyze.mozilla_tls_profile.tls_config_checker import (
    MozillaTlsConfiguration,
    ServerNotCompliantWithTlsConfiguration,
    ServerScanResultIncomplete,
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


class TestMozillaTlsConfigurationChecker:
    @pytest.mark.skip("Server needs to be updated; check https://github.com/chromium/badssl.com/issues/483")
    def test_badssl_compliant_with_old(self):
        # Given the scan results for a server that is compliant with the "old" Mozilla config
        scanner = Scanner()
        scanner.queue_scans(
            [ServerScanRequest(server_location=ServerNetworkLocation(hostname="mozilla-old.badssl.com"))]
        )
        server_scan_result = next(scanner.get_results())

        # When checking if the server is compliant with the Mozilla "old" TLS config
        # It succeeds and the server is returned as compliant
        tls_config = MozillaTlsConfiguration.get(TlsConfigurationEnum.MOZILLA_OLD)
        check_server_against_tls_configuration(
            server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
        )

        # And the server is returned as NOT compliant for the other Mozilla configs
        for mozilla_config_enum in [TlsConfigurationEnum.MOZILLA_INTERMEDIATE, TlsConfigurationEnum.MOZILLA_MODERN]:
            tls_config = MozillaTlsConfiguration.get(mozilla_config_enum)
            with pytest.raises(ServerNotCompliantWithTlsConfiguration):
                check_server_against_tls_configuration(
                    server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
                )

    @pytest.mark.skip("Server needs to be updated; check https://github.com/chromium/badssl.com/issues/483")
    def test_badssl_compliant_with_intermediate(self):
        # Given the scan results for a server that is compliant with the "intermediate" Mozilla config
        scanner = Scanner()
        scanner.queue_scans(
            [ServerScanRequest(server_location=ServerNetworkLocation(hostname="mozilla-intermediate.badssl.com"))]
        )
        server_scan_result = next(scanner.get_results())

        # When checking if the server is compliant with the Mozilla "intermediate" TLS config
        # It succeeds and the server is returned as compliant
        tls_config = MozillaTlsConfiguration.get(TlsConfigurationEnum.MOZILLA_INTERMEDIATE)
        check_server_against_tls_configuration(
            server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
        )

        # And the server is returned as NOT compliant for the other Mozilla configs
        for mozilla_config in [TlsConfigurationEnum.MOZILLA_OLD, TlsConfigurationEnum.MOZILLA_MODERN]:
            tls_config = MozillaTlsConfiguration.get(mozilla_config)
            with pytest.raises(ServerNotCompliantWithTlsConfiguration):
                check_server_against_tls_configuration(
                    server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
                )

    @pytest.mark.skip("Server needs to be updated; check https://github.com/chromium/badssl.com/issues/483")
    def test_badssl_compliant_with_modern(self):
        # Given the scan results for a server that is compliant with the "modern" Mozilla config
        scanner = Scanner()
        scanner.queue_scans(
            [ServerScanRequest(server_location=ServerNetworkLocation(hostname="mozilla-modern.badssl.com"))]
        )
        server_scan_result = next(scanner.get_results())

        # When checking if the server is compliant with the Mozilla "modern" TLS config
        # It succeeds and the server is returned as compliant
        tls_config = MozillaTlsConfiguration.get(TlsConfigurationEnum.MOZILLA_MODERN)
        check_server_against_tls_configuration(
            server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
        )

        # And the server is returned as NOT compliant for the other Mozilla configs
        for mozilla_config in [TlsConfigurationEnum.MOZILLA_OLD, TlsConfigurationEnum.MOZILLA_INTERMEDIATE]:
            tls_config = MozillaTlsConfiguration.get(mozilla_config)
            with pytest.raises(ServerNotCompliantWithTlsConfiguration):
                check_server_against_tls_configuration(
                    server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
                )

    def test_solo_cert_deployment_compliant_with_old(self):
        # Given the scan results for a server that is compliant with the "old" Mozilla config
        scanner = Scanner()
        scanner.queue_scans([ServerScanRequest(server_location=ServerNetworkLocation(hostname="www.mozilla.com"))])
        server_scan_result = next(scanner.get_results())

        # When checking if the server is compliant with the Mozilla "old" TLS config
        # It succeeds and the server is returned as compliant
        tls_config = MozillaTlsConfiguration.get(TlsConfigurationEnum.MOZILLA_OLD)
        check_server_against_tls_configuration(
            server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
        )

    def test_multi_certs_deployment_compliant_with_old(self):
        # TODO(AD): Implement this test
        pass

    def test_multi_certs_deployment_not_compliant_with_intermediate(self, server_scan_result_for_google):
        # Give the scan results for google.com which has multiple leaf certificates
        # When checking if the server is compliant with the Mozilla "intermediate" TLS config
        tls_config = MozillaTlsConfiguration.get(TlsConfigurationEnum.MOZILLA_INTERMEDIATE)

        # It succeeds and the server is returned as NOT compliant
        with pytest.raises(ServerNotCompliantWithTlsConfiguration):
            check_server_against_tls_configuration(
                server_scan_result=server_scan_result_for_google, tls_config_to_check_against=tls_config
            )

    def test_multi_certs_deployment_not_compliant_with_modern(self, server_scan_result_for_google):
        # Give the scan results for google.com which has multiple leaf certificates
        # When checking if the server is compliant with the Mozilla "modern" TLS config
        tls_config = MozillaTlsConfiguration.get(TlsConfigurationEnum.MOZILLA_MODERN)

        # It succeeds and the server is returned as NOT compliant
        with pytest.raises(ServerNotCompliantWithTlsConfiguration):
            check_server_against_tls_configuration(
                server_scan_result=server_scan_result_for_google, tls_config_to_check_against=tls_config
            )

    def test_incomplete_scan_result(self):
        # Given a scan result that does not contain all the information needed by the Mozilla checker
        server_scan_result = ServerScanResultFactory.create()

        # When checking the server is compliant
        tls_config = MozillaTlsConfiguration.get(TlsConfigurationEnum.MOZILLA_MODERN)
        # It fails
        with pytest.raises(ServerScanResultIncomplete):
            check_server_against_tls_configuration(
                server_scan_result=server_scan_result, tls_config_to_check_against=tls_config
            )
