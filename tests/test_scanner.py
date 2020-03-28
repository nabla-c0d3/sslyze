from collections import Counter
from concurrent.futures._base import as_completed
from unittest import mock

import pytest

from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner import Scanner, ScanCommandErrorReasonEnum, ServerScanRequest
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.factories import ServerConnectivityInfoFactory
from tests.markers import can_only_run_on_linux_64
from tests.mock_plugins import (
    MockPlugin1ScanResult,
    MockPlugin2ScanResult,
    MockPlugin1ExtraArguments,
    ScanCommandForTests,
    ScanCommandForTestsRepository,
)
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


class TestServerScanRequest:
    def test_with_extra_arguments_but_no_corresponding_scan_command(self):
        # When trying to queue a scan for a server
        with pytest.raises(ValueError):
            ServerScanRequest(
                server_info=ServerConnectivityInfoFactory.create(),
                # With an extra argument for one command
                scan_commands_extra_arguments={
                    ScanCommandForTests.MOCK_COMMAND_1: MockPlugin1ExtraArguments(extra_field="test")
                },
                # But that specific scan command was not queued
                scan_commands={ScanCommandForTests.MOCK_COMMAND_2},
            )
            # It fails


class TestScanner:
    @mock.patch("sslyze.scanner.ScanCommandsRepository", ScanCommandForTestsRepository)
    def test(self):
        # Given a server to scan
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={ScanCommandForTests.MOCK_COMMAND_1, ScanCommandForTests.MOCK_COMMAND_2},
        )

        # When queuing the scan
        scanner = Scanner()
        scanner.queue_scan(server_scan)

        # It succeeds
        all_results = []
        for result in scanner.get_results():
            all_results.append(result)

            # And the right result is returned
            assert result.server_info == server_scan.server_info
            assert result.scan_commands == server_scan.scan_commands
            assert result.scan_commands_extra_arguments == server_scan.scan_commands_extra_arguments
            assert len(result.scan_commands_results) == 2

            assert type(result.scan_commands_results[ScanCommandForTests.MOCK_COMMAND_1]) == MockPlugin1ScanResult
            assert type(result.scan_commands_results[ScanCommandForTests.MOCK_COMMAND_2]) == MockPlugin2ScanResult

        assert len(all_results) == 1

    @mock.patch("sslyze.scanner.ScanCommandsRepository", ScanCommandForTestsRepository)
    def test_duplicate_server(self):
        # Given a server to scan
        server_info = ServerConnectivityInfoFactory.create()

        # When trying to queue two scans for this server
        server_scan1 = ServerScanRequest(server_info=server_info, scan_commands={ScanCommandForTests.MOCK_COMMAND_1})
        server_scan2 = ServerScanRequest(server_info=server_info, scan_commands={ScanCommandForTests.MOCK_COMMAND_2})
        scanner = Scanner()
        scanner.queue_scan(server_scan1)

        # It fails
        with pytest.raises(ValueError):
            scanner.queue_scan(server_scan2)

    @mock.patch("sslyze.scanner.ScanCommandsRepository", ScanCommandForTestsRepository)
    def test_with_extra_arguments(self):
        # Given a server to scan
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={ScanCommandForTests.MOCK_COMMAND_1},
            # With an extra argument for one command
            scan_commands_extra_arguments={
                ScanCommandForTests.MOCK_COMMAND_1: MockPlugin1ExtraArguments(extra_field="test")
            },
        )

        # When queuing the scan
        scanner = Scanner()
        scanner.queue_scan(server_scan)

        # It succeeds
        all_results = []
        for result in scanner.get_results():
            all_results.append(result)

            # And the extra argument was taken into account
            assert result.scan_commands_extra_arguments == server_scan.scan_commands_extra_arguments

        assert len(all_results) == 1

    @mock.patch("sslyze.scanner.ScanCommandsRepository", ScanCommandForTestsRepository)
    def test_exception_when_scheduling_jobs(self):
        # Given a server to scan
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={
                ScanCommandForTests.MOCK_COMMAND_1,
                # And one of the scan commands will trigger an exception when scheduling scan jobs
                ScanCommandForTests.MOCK_COMMAND_EXCEPTION_WHEN_SCHEDULING_JOBS,
            },
        )

        # When queuing the scan
        scanner = Scanner()
        scanner.queue_scan(server_scan)

        # It succeeds
        all_results = []
        for result in scanner.get_results():
            all_results.append(result)

            assert result.server_info == server_scan.server_info
            assert result.scan_commands == server_scan.scan_commands
            assert result.scan_commands_extra_arguments == server_scan.scan_commands_extra_arguments
            assert len(result.scan_commands_results) == 1

            # And the exception was properly caught and returned
            assert len(result.scan_commands_errors) == 1
            error = result.scan_commands_errors[ScanCommandForTests.MOCK_COMMAND_EXCEPTION_WHEN_SCHEDULING_JOBS]
            assert ScanCommandErrorReasonEnum.BUG_IN_SSLYZE == error.reason
            assert error.exception_trace

        assert len(all_results) == 1

    @mock.patch("sslyze.scanner.ScanCommandsRepository", ScanCommandForTestsRepository)
    def test_exception_when_processing_jobs(self):
        # Given a server to scan
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={
                ScanCommandForTests.MOCK_COMMAND_1,
                # And one of the scan commands will trigger an exception when processing the completed scan jobs
                ScanCommandForTests.MOCK_COMMAND_EXCEPTION_WHEN_PROCESSING_JOBS,
            },
        )

        # When queuing the scan
        scanner = Scanner()
        scanner.queue_scan(server_scan)

        # It succeeds
        all_results = []
        for result in scanner.get_results():
            all_results.append(result)

            assert result.server_info == server_scan.server_info
            assert result.scan_commands == server_scan.scan_commands
            assert result.scan_commands_extra_arguments == server_scan.scan_commands_extra_arguments
            assert len(result.scan_commands_results) == 1

            # And the exception was properly caught and returned
            assert len(result.scan_commands_errors) == 1
            error = result.scan_commands_errors[ScanCommandForTests.MOCK_COMMAND_EXCEPTION_WHEN_PROCESSING_JOBS]
            assert ScanCommandErrorReasonEnum.BUG_IN_SSLYZE == error.reason
            assert error.exception_trace

        assert len(all_results) == 1

    @can_only_run_on_linux_64
    def test_client_certificate_missing(self):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = ServerConnectivityTester().perform(server_location)

            server_scan = ServerScanRequest(
                server_info=server_info,
                scan_commands={
                    # And a scan command that cannot be completed without a client certificate
                    ScanCommand.HTTP_HEADERS,
                },
            )

            # When queuing the scan
            scanner = Scanner()
            scanner.queue_scan(server_scan)

            # It succeeds
            all_results = []
            for result in scanner.get_results():
                all_results.append(result)

            assert len(all_results) == 1

            # And the error was properly returned
            error = all_results[0].scan_commands_errors[ScanCommand.HTTP_HEADERS]
            assert error.reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED


class TestScannerInternals:
    @mock.patch("sslyze.scanner.ScanCommandsRepository", ScanCommandForTestsRepository)
    def test(self):
        # Given a lot of servers to scan
        total_server_scans_count = 100
        server_scans = [
            ServerScanRequest(
                server_info=ServerConnectivityInfoFactory.create(),
                scan_commands={ScanCommandForTests.MOCK_COMMAND_1, ScanCommandForTests.MOCK_COMMAND_2},
            )
            for _ in range(total_server_scans_count)
        ]

        # And a scanner with specifically chosen network settings
        per_server_concurrent_connections_limit = 4
        concurrent_server_scans_limit = 20
        scanner = Scanner(per_server_concurrent_connections_limit, concurrent_server_scans_limit)

        # When queuing the scans, it succeeds
        for scan in server_scans:
            scanner.queue_scan(scan)

        # And the right number of scans was performed
        assert total_server_scans_count == len(scanner._queued_server_scans)
        assert total_server_scans_count == len(scanner._server_to_thread_pool)

        # And the chosen network settings were used
        assert concurrent_server_scans_limit == len(scanner._all_thread_pools)
        for pool in scanner._all_thread_pools:
            assert per_server_concurrent_connections_limit == pool._max_workers

        # And the server scans were evenly distributed among the thread pools to maximize performance
        expected_server_scans_per_pool = int(total_server_scans_count / concurrent_server_scans_limit)
        server_scans_per_pool_count = Counter(scanner._server_to_thread_pool.values())
        for pool_count in server_scans_per_pool_count.values():
            assert expected_server_scans_per_pool == pool_count

    @mock.patch("sslyze.scanner.ScanCommandsRepository", ScanCommandForTestsRepository)
    def test_emergency_shutdown(self):
        # Given a lot of servers to scan
        total_server_scans_count = 100
        server_scans = [
            ServerScanRequest(
                server_info=ServerConnectivityInfoFactory.create(),
                scan_commands={ScanCommandForTests.MOCK_COMMAND_1, ScanCommandForTests.MOCK_COMMAND_2},
            )
            for _ in range(total_server_scans_count)
        ]

        # And the scans get queued
        scanner = Scanner()
        for scan in server_scans:
            scanner.queue_scan(scan)

        # When trying to quickly shutdown the scanner, it succeeds
        scanner.emergency_shutdown()

        # And all the queued jobs were done or cancelled
        for completed_future in as_completed(scanner._queued_future_to_server_and_scan_cmd.keys()):
            assert completed_future.done()
