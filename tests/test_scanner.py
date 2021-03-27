import threading
from queue import Queue
from unittest import mock

import pytest

from sslyze.errors import TlsHandshakeTimedOut
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
    MockPlugin1Implementation,
)
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


@pytest.fixture
def mock_scan_commands():
    with mock.patch("sslyze.scanner._queued_server_scan.ScanCommandsRepository", ScanCommandForTestsRepository):
        yield


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
    def test(self, mock_scan_commands):
        # Given a server to scan
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={ScanCommandForTests.MOCK_COMMAND_1, ScanCommandForTests.MOCK_COMMAND_2},
        )

        # When running the scan
        scanner = Scanner()
        scanner.start_scans([server_scan])

        # It succeeds
        all_results = []
        for result in scanner.get_results():
            all_results.append(result)
        assert len(all_results) == 1

        # And the right result is returned
        result = all_results[0]
        assert result.server_info == server_scan.server_info
        assert result.scan_commands == server_scan.scan_commands
        assert result.scan_commands_extra_arguments == server_scan.scan_commands_extra_arguments
        assert len(result.scan_commands_results) == 2

        assert type(result.scan_commands_results[ScanCommandForTests.MOCK_COMMAND_1]) == MockPlugin1ScanResult
        assert type(result.scan_commands_results[ScanCommandForTests.MOCK_COMMAND_2]) == MockPlugin2ScanResult

        # And the Scanner instance is all done and cleaned up
        assert not scanner._are_server_scans_ongoing

    def test_with_extra_arguments(self, mock_scan_commands):
        # Given a server to scan with a scan command
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={ScanCommandForTests.MOCK_COMMAND_1},
            # And the command takes an extra argument
            scan_commands_extra_arguments={
                ScanCommandForTests.MOCK_COMMAND_1: MockPlugin1ExtraArguments(extra_field="test")
            },
        )

        # When running the scan
        scanner = Scanner()
        scanner.start_scans([server_scan])

        # It succeeds
        all_results = []
        for result in scanner.get_results():
            all_results.append(result)
        assert len(all_results) == 1

        # And the extra argument was taken into account
        assert all_results[0].scan_commands_extra_arguments == server_scan.scan_commands_extra_arguments

    def test_error_bug_in_sslyze_when_scheduling_jobs(self, mock_scan_commands):
        # Given a server to scan with some scan commands
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={ScanCommandForTests.MOCK_COMMAND_1, ScanCommandForTests.MOCK_COMMAND_2},
        )

        # And the first scan command will trigger an error when generating scan jobs
        with mock.patch.object(MockPlugin1Implementation, "scan_jobs_for_scan_command", side_effect=RuntimeError):
            # When running the scan
            scanner = Scanner()
            scanner.start_scans([server_scan])

            # It succeeds
            all_results = []
            for result in scanner.get_results():
                all_results.append(result)
            assert len(all_results) == 1

            # And the exception was properly caught and returned
            result = all_results[0]
            assert len(result.scan_commands_errors) == 1
            error = result.scan_commands_errors[ScanCommandForTests.MOCK_COMMAND_1]
            assert ScanCommandErrorReasonEnum.BUG_IN_SSLYZE == error.reason
            assert error.exception_trace

    def test_error_bug_in_sslyze_when_processing_job_results(self, mock_scan_commands):
        # Given a server to scan with some scan commands
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={ScanCommandForTests.MOCK_COMMAND_1, ScanCommandForTests.MOCK_COMMAND_2},
        )

        # And the first scan command will trigger an error when processing the completed scan jobs
        with mock.patch.object(MockPlugin1Implementation, "_scan_job_work_function", side_effect=RuntimeError):
            # When running the scan
            scanner = Scanner()
            scanner.start_scans([server_scan])

            # It succeeds
            all_results = []
            for result in scanner.get_results():
                all_results.append(result)
            assert len(all_results) == 1

            # And the exception was properly caught and returned
            result = all_results[0]
            assert len(result.scan_commands_errors) == 1
            error = result.scan_commands_errors[ScanCommandForTests.MOCK_COMMAND_1]
            assert ScanCommandErrorReasonEnum.BUG_IN_SSLYZE == error.reason
            assert error.exception_trace

    @can_only_run_on_linux_64
    def test_error_client_certificate_needed(self):
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

            # When running the scan
            scanner = Scanner()
            scanner.start_scans([server_scan])

            # It succeeds
            all_results = []
            for result in scanner.get_results():
                all_results.append(result)
            assert len(all_results) == 1

            # And the error was properly returned
            error = all_results[0].scan_commands_errors[ScanCommand.HTTP_HEADERS]
            assert error.reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED

    def test_error_server_connectivity_issue_handshake_timeout(self, mock_scan_commands):
        # Given a server to scan with some commands
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={ScanCommandForTests.MOCK_COMMAND_1, ScanCommandForTests.MOCK_COMMAND_2},
        )

        # And the first scan command will trigger a handshake timeout with the server
        with mock.patch.object(
            MockPlugin1Implementation,
            "_scan_job_work_function",
            side_effect=TlsHandshakeTimedOut(
                server_location=server_scan.server_info.server_location,
                network_configuration=server_scan.server_info.network_configuration,
                error_message="error",
            ),
        ):
            # When running the scan
            scanner = Scanner()
            scanner.start_scans([server_scan])

            # It succeeds
            all_results = []
            for result in scanner.get_results():
                all_results.append(result)
            assert len(all_results) == 1

            # And the error was properly caught and returned
            result = all_results[0]
            assert len(result.scan_commands_errors) == 1
            error = result.scan_commands_errors[ScanCommandForTests.MOCK_COMMAND_1]
            assert ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE == error.reason
            assert error.exception_trace

    def test_enforces_per_server_concurrent_connections_limit(self, mock_scan_commands):
        # Given a server to scan with a scan command that requires multiple connections/jobs to the server
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(), scan_commands={ScanCommandForTests.MOCK_COMMAND_1},
        )

        # And a scanner configured to only perform one concurrent connection per server scan
        scanner = Scanner(per_server_concurrent_connections_limit=1)

        # And the scan command will notify us when more than one connection is being performed concurrently
        # Test internals: setup plumbing to detect when more than one thread are running at the same time
        # We use a Barrier that waits for 2 concurrent threads, and puts True in a queue if that ever happens
        queue = Queue()

        def flag_concurrent_threads_running():
            # Only called when two threads are running at the same time
            queue.put(True)

        barrier = threading.Barrier(parties=2, action=flag_concurrent_threads_running, timeout=1)

        def scan_job_work_function(arg1: str, arg2: int):
            barrier.wait()

        with mock.patch.object(MockPlugin1Implementation, "_scan_job_work_function", scan_job_work_function):
            # When running the scan
            scanner.start_scans([server_scan])

            # It succeeds
            all_results = []
            for result in scanner.get_results():
                all_results.append(result)
            assert len(all_results) == 1

            # And there never was more than one thread (=1 job/connection) running at the same time
            assert queue.empty()
