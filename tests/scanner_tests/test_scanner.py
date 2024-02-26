from unittest import mock

from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerScanStatusEnum,
    ServerScanResult,
    ServerTlsProbingResult,
    ServerNetworkLocation,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    ScanCommandErrorReasonEnum,
)
from sslyze.errors import ConnectionToServerFailed
from sslyze.scanner import _mass_connectivity_tester
from sslyze.scanner.scanner_observer import ScannerObserver
from tests.factories import ServerScanRequestFactory, ServerTlsProbingResultFactory
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


class _MockScannerObserver(ScannerObserver):
    def __init__(self):
        self.server_connectivity_test_error_calls_count = 0
        self.server_connectivity_test_completed_calls_count = 0
        self.server_scan_completed_calls_count = 0
        self.all_server_scans_completed_calls_count = 0

    def server_connectivity_test_error(
        self, server_scan_request: ServerScanRequest, connectivity_error: ConnectionToServerFailed
    ) -> None:
        self.server_connectivity_test_error_calls_count += 1

    def server_connectivity_test_completed(
        self, server_scan_request: ServerScanRequest, connectivity_result: ServerTlsProbingResult
    ) -> None:
        self.server_connectivity_test_completed_calls_count += 1

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        self.server_scan_completed_calls_count += 1

    def all_server_scans_completed(self) -> None:
        self.all_server_scans_completed_calls_count += 1


class TestScanner:
    def test(self, mock_scan_commands):
        # Given a bunch of servers to scan
        all_scan_requests = [ServerScanRequestFactory.create() for _ in range(20)]

        # And all the servers will be reachable
        connectivity_result = ServerTlsProbingResultFactory.create()
        with mock.patch.object(
            _mass_connectivity_tester, "check_connectivity_to_server", return_value=connectivity_result
        ):
            # And given an observer to monitor scans
            observer = _MockScannerObserver()

            # When running the scans with the observer
            scanner = Scanner(observers=[observer])
            scanner.queue_scans(all_scan_requests)
            assert scanner._has_started_work

            # It succeeds
            all_scan_results = []
            for result in scanner.get_results():
                all_scan_results.append(result)

        # And the right results were returned
        assert len(all_scan_results) == len(all_scan_requests)
        assert {result.scan_status for result in all_scan_results} == {ServerScanStatusEnum.COMPLETED}

        # And the observer was called appropriately
        assert observer.server_connectivity_test_error_calls_count == 0
        assert observer.server_connectivity_test_completed_calls_count == len(all_scan_requests)
        assert observer.server_scan_completed_calls_count == len(all_scan_requests)
        assert observer.all_server_scans_completed_calls_count == 1

    def test_connectivity_error(self, mock_scan_commands):
        # Given a server to scan
        scan_request = ServerScanRequestFactory.create()

        # And the server will NOT be reachable
        error = ConnectionToServerFailed(
            server_location=scan_request.server_location,
            network_configuration=scan_request.network_configuration,
            error_message="testt",
        )
        with mock.patch.object(_mass_connectivity_tester, "check_connectivity_to_server", side_effect=error):
            # And given an observer to monitor scans
            observer = _MockScannerObserver()

            # When running the scans with the observer
            scanner = Scanner(observers=[observer])
            scanner.queue_scans([scan_request])

            # It succeeds
            all_scan_results = []
            for result in scanner.get_results():
                all_scan_results.append(result)

        # And the right result was returned
        assert len(all_scan_results) == 1
        assert all_scan_results[0].scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY

        # And the observer was called appropriately
        assert observer.server_connectivity_test_error_calls_count == 1
        assert observer.server_connectivity_test_completed_calls_count == 0
        assert observer.server_scan_completed_calls_count == 1
        assert observer.all_server_scans_completed_calls_count == 1

    @can_only_run_on_linux_64
    def test_error_client_certificate_needed(self):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And a scan request for it that does NOT provide a client certificate
            scan_request = ServerScanRequest(
                server_location=ServerNetworkLocation(
                    hostname=server.hostname, ip_address=server.ip_address, port=server.port
                ),
                scan_commands={
                    # And the request has a scan command that cannot be completed without a client certificate
                    ScanCommand.HTTP_HEADERS,
                },
            )

            # When running the scan
            scanner = Scanner()
            scanner.queue_scans([scan_request])

            # It succeeds
            all_results = []
            for result in scanner.get_results():
                all_results.append(result)

        # And the right result was returned
        assert len(all_results) == 1

        # And the fact that a client certificate is needed was properly returned
        http_headers_result = all_results[0].scan_result.http_headers
        assert http_headers_result.status == ScanCommandAttemptStatusEnum.ERROR
        assert http_headers_result.error_reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED
        assert http_headers_result.error_trace
        assert http_headers_result.result is None
