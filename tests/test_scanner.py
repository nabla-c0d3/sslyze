from typing import cast

import pytest

from sslyze.plugins.certificate_info.scan_commands import CertificateInfoScanResult
from sslyze.plugins.plugin_base import ServerScanRequest
from sslyze.plugins.scan_commands import ScanCommandEnum
from sslyze.scanner import Scanner
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection


# TODO(AD): Create a lightweight plugin instead of using certinfo
class TestScanner:

    def test(self):
        # Given a server to scan
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When queuing the scan
        server_scan = ServerScanRequest(
            server_info=server_info,
            scan_commands={ScanCommandEnum.CERTIFICATE_INFO},
        )
        scanner = Scanner()
        scanner.queue_scan(server_scan)

        # It succeeds
        all_results = []
        for result in scanner.get_results():
            all_results.append(result)

            # And the right result is returned
            assert result.server_info == server_info
            assert result.scan_commands == server_scan.scan_commands
            assert result.scan_commands_extra_arguments == server_scan.scan_commands_extra_arguments
            assert len(result.scan_commands_results) == 1

            assert type(result.scan_commands_results[ScanCommandEnum.CERTIFICATE_INFO]) == CertificateInfoScanResult
            cmd_result = cast(CertificateInfoScanResult, result.scan_commands_results[ScanCommandEnum.CERTIFICATE_INFO])
            assert cmd_result.received_certificate_chain
            assert cmd_result.verified_certificate_chain

        assert len(all_results) == 1

    def test_duplicate_server(self):
        # Given a server to scan
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When trying to queue two scans for this server
        server_scan1 = ServerScanRequest(
            server_info=server_info,
            scan_commands={ScanCommandEnum.CERTIFICATE_INFO},
        )
        server_scan2 = ServerScanRequest(
            server_info=server_info,
            scan_commands={ScanCommandEnum.COMPRESSION},
        )
        scanner = Scanner()
        scanner.queue_scan(server_scan1)

        # It fails
        with pytest.raises(ValueError):
            scanner.queue_scan(server_scan2)
