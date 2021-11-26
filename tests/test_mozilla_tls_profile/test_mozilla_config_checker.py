import pytest

from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
from sslyze.mozilla_tls_profile.mozilla_config_checker import (
    MozillaTlsConfigurationChecker,
    MozillaTlsConfigurationEnum,
    ServerNotCompliantWithMozillaTlsConfiguration,
    ServerScanResultIncomplete,
)

# Use session as the scope so we only run this scan once through the test suite
from tests.factories import ServerScanResultFactory


@pytest.fixture(scope="session")
def server_scan_result_for_google():
    scanner = Scanner()
    scanner.queue_scans([ServerScanRequest(server_location=ServerNetworkLocation(hostname="google.com"))])
    for server_scan_result in scanner.get_results():
        yield server_scan_result


class TestMozillaTlsConfigurationChecker:
    def test_google_compliant_with_old(self, server_scan_result_for_google):
        # Give the scan results for google.com
        # When checking if the server is compliant with the Mozilla "old" TLS config
        checker = MozillaTlsConfigurationChecker.get_default()

        # It succeeds and the server is returned as compliant
        checker.check_server(
            against_config=MozillaTlsConfigurationEnum.OLD, server_scan_result=server_scan_result_for_google,
        )

    def test_google_not_compliant_with_intermediate(self, server_scan_result_for_google):
        # Give the scan results for google.com
        # When checking if the server is compliant with the Mozilla "intermediate" TLS config
        checker = MozillaTlsConfigurationChecker.get_default()

        # It succeeds and the server is returned as NOT compliant
        with pytest.raises(ServerNotCompliantWithMozillaTlsConfiguration):
            checker.check_server(
                against_config=MozillaTlsConfigurationEnum.INTERMEDIATE,
                server_scan_result=server_scan_result_for_google,
            )

    def test_google_not_compliant_with_modern(self, server_scan_result_for_google):
        # Give the scan results for google.com
        # When checking if the server is compliant with the Mozilla "modern" TLS config
        checker = MozillaTlsConfigurationChecker.get_default()

        # It succeeds and the server is returned as NOT compliant
        with pytest.raises(ServerNotCompliantWithMozillaTlsConfiguration):
            checker.check_server(
                against_config=MozillaTlsConfigurationEnum.MODERN, server_scan_result=server_scan_result_for_google,
            )

    def test_incomplete_scan_result(self):
        # Given a scan result that does not contain all the information needed by the Mozilla checker
        server_scan_result = ServerScanResultFactory.create()

        # When checking the server is compliant
        checker = MozillaTlsConfigurationChecker.get_default()
        # It fails
        with pytest.raises(ServerScanResultIncomplete):
            checker.check_server(
                against_config=MozillaTlsConfigurationEnum.MODERN, server_scan_result=server_scan_result,
            )
