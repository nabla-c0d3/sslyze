import threading
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from typing import List, Optional
from unittest import mock

import pytest

from sslyze import CertificateInfoExtraArgument
from sslyze.errors import TlsHandshakeTimedOut
from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandResult,
    ScanCommandExtraArgument,
    ScanJob,
    ScanJobResult,
)
from sslyze.plugins.scan_commands import ScanCommandsRepository
from sslyze import (
    Scanner,
    ScanCommand,
    ScanCommandErrorReasonEnum,
    ServerScanRequest,
    ScanCommandsExtraArguments,
    ServerConnectivityTester,
    ServerConnectivityInfo,
    ServerNetworkLocationViaDirectConnection,
)
from tests.factories import ServerConnectivityInfoFactory, ServerScanResultFactory
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ClientAuthConfigEnum


@dataclass(frozen=True)
class _MockPluginScanResult(ScanCommandResult):
    results_field: List[str]


class _MockPluginImplementation(ScanCommandImplementation):

    result_cls = _MockPluginScanResult
    _scan_jobs_count = 5

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        # Create a bunch of "do nothing" jobs to imitate a real plugin
        scan_jobs = [
            ScanJob(function_to_call=cls._scan_job_work_function, function_arguments=["test", 12])
            for _ in range(cls._scan_jobs_count)
        ]
        return scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> ScanCommandResult:
        if len(scan_job_results) != cls._scan_jobs_count:
            raise AssertionError("Did not receive all the scan jobs that needed to be completed")

        return cls.result_cls(results_field=[result.get_result() for result in scan_job_results])  # type: ignore

    @staticmethod
    def _scan_job_work_function(arg1: str, arg2: int) -> str:
        return f"{arg1}-{arg2}-did nothing"


@pytest.fixture
def mock_scan_commands():
    """Make all scan commands point to a mock implementation so that no actual scans are performed.
    """
    with mock.patch.object(ScanCommandsRepository, "get_implementation_cls", return_value=_MockPluginImplementation):
        yield


class TestServerScanRequest:
    def test_scan_command_results_match_scan_command_names(self):
        # Given a the results of a server scan
        scan_result = ServerScanResultFactory.create()

        # There's a result field for each scan command available in SSLyze
        for scan_command in ScanCommand:
            getattr(scan_result.scan_commands_results, scan_command)

    def test_with_extra_arguments_but_no_corresponding_scan_command(self):
        # When trying to queue a scan for a server
        with pytest.raises(ValueError):
            ServerScanRequest(
                server_info=ServerConnectivityInfoFactory.create(),
                # With an extra argument for one command
                scan_commands_extra_arguments=ScanCommandsExtraArguments(
                    certificate_info=CertificateInfoExtraArgument(custom_ca_file=Path(__file__))
                ),
                # But that specific scan command was not queued
                scan_commands={ScanCommand.ROBOT},
            )
            # It fails


class TestScanner:
    def test(self, mock_scan_commands):
        # Given a server to scan
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.ROBOT},
        )

        # When running the scan
        scanner = Scanner()
        scanner.start_scans([server_scan])

        # It succeeds
        all_results = []
        for server_result in scanner.get_results():
            all_results.append(server_result)
        assert len(all_results) == 1

        # And the right result is returned
        server_result = all_results[0]
        assert server_result.server_info == server_scan.server_info
        assert server_result.scan_commands == server_scan.scan_commands
        assert server_result.scan_commands_extra_arguments == server_scan.scan_commands_extra_arguments

        # And the scheduled scan commands have results
        assert len(server_result.scan_commands_results.scan_commands_with_result()) == 2
        assert server_result.scan_commands_results.certificate_info
        assert server_result.scan_commands_results.robot

        # And the Scanner instance is all done and cleaned up
        assert not scanner._are_server_scans_ongoing

    def test_with_extra_arguments(self, mock_scan_commands):
        # Given a server to scan with a scan command
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(),
            scan_commands={ScanCommand.CERTIFICATE_INFO},
            # And the command takes an extra argument
            scan_commands_extra_arguments=ScanCommandsExtraArguments(
                certificate_info=CertificateInfoExtraArgument(custom_ca_file=Path(__file__))
            ),
        )

        # When running the scan
        scanner = Scanner()
        scanner.start_scans([server_scan])

        # It succeeds
        all_results = []
        for result in scanner.get_results():
            all_results.append(result)
        assert len(all_results) == 1
        assert all_results[0].scan_commands_results.certificate_info

        # And the extra argument was taken into account
        assert all_results[0].scan_commands_extra_arguments == server_scan.scan_commands_extra_arguments

    def test_error_bug_in_sslyze_when_scheduling_jobs(self):
        # Given a server to scan with one scan command
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(), scan_commands={ScanCommand.CERTIFICATE_INFO},
        )

        # And the scan command will trigger an error when generating scan jobs
        class PluginImplThatCrashesWhenCreatingJobs(ScanCommandImplementation):
            @classmethod
            def scan_jobs_for_scan_command(
                cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
            ) -> List[ScanJob]:
                raise KeyError("Some unexpected error when generating scan jobs")

        with mock.patch.object(
            ScanCommandsRepository, "get_implementation_cls", return_value=PluginImplThatCrashesWhenCreatingJobs
        ):
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
            error = result.scan_commands_errors[0]
            assert ScanCommand.CERTIFICATE_INFO == error.scan_command
            assert ScanCommandErrorReasonEnum.BUG_IN_SSLYZE == error.reason
            assert error.exception_trace

    def test_error_bug_in_sslyze_when_processing_job_results(self):
        # Given a server to scan with one scan command
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(), scan_commands={ScanCommand.CERTIFICATE_INFO},
        )

        # And the scan command will trigger an error when processing completed scan jobs
        class PluginImplThatCrashesWhenProcessingJobs(ScanCommandImplementation):
            @staticmethod
            def _scan_job_work_function(arg1: str) -> str:
                return f"{arg1}-do nothing"

            @classmethod
            def scan_jobs_for_scan_command(
                cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
            ) -> List[ScanJob]:
                scan_jobs = [
                    ScanJob(function_to_call=cls._scan_job_work_function, function_arguments=["test"]) for _ in range(5)
                ]
                return scan_jobs

            @classmethod
            def result_for_completed_scan_jobs(
                cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
            ) -> ScanCommandResult:
                raise KeyError("Some unexpected error when processing scan jobs")

        with mock.patch.object(
            ScanCommandsRepository, "get_implementation_cls", return_value=PluginImplThatCrashesWhenProcessingJobs
        ):
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
            error = result.scan_commands_errors[0]
            assert ScanCommand.CERTIFICATE_INFO == error.scan_command
            assert ScanCommandErrorReasonEnum.BUG_IN_SSLYZE == error.reason
            assert error.exception_trace

    def test_error_server_connectivity_issue_handshake_timeout(self):
        # Given a server to scan with a scan command
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(), scan_commands={ScanCommand.CERTIFICATE_INFO},
        )

        # And the scan command will trigger a connectivity error when doing work
        class PluginImplThatTriggersConnectivityError(ScanCommandImplementation):
            @staticmethod
            def _scan_job_work_function(arg1: str) -> str:
                raise TlsHandshakeTimedOut(
                    server_location=server_scan.server_info.server_location,
                    network_configuration=server_scan.server_info.network_configuration,
                    error_message="error",
                )

            @classmethod
            def scan_jobs_for_scan_command(
                cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
            ) -> List[ScanJob]:
                return [ScanJob(function_to_call=cls._scan_job_work_function, function_arguments=["test"])]

            @classmethod
            def result_for_completed_scan_jobs(
                cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
            ) -> ScanCommandResult:
                for completed_job in scan_job_results:
                    # This should trigger the exception from _scan_job_work_function()
                    completed_job.get_result()
                return _MockPluginScanResult(results_field=["ok"])

        with mock.patch.object(
            ScanCommandsRepository, "get_implementation_cls", return_value=PluginImplThatTriggersConnectivityError
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
            error = result.scan_commands_errors[0]
            assert ScanCommand.CERTIFICATE_INFO == error.scan_command
            assert ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE == error.reason
            assert error.exception_trace

    def test_enforces_per_server_concurrent_connections_limit(self):
        # Given a server to scan with a scan command
        server_scan = ServerScanRequest(
            server_info=ServerConnectivityInfoFactory.create(), scan_commands={ScanCommand.CERTIFICATE_INFO},
        )

        # And a scanner configured to only perform one concurrent connection per server scan
        scanner = Scanner(per_server_concurrent_connections_limit=1)

        # And the scan scan command requires multiple connections/jobs to the server
        # And the scan command will notify us when more than one connection is being performed concurrently
        # Test internals: setup plumbing to detect when more than one thread are running at the same time
        # We use a Barrier that waits for 2 concurrent threads, and puts True in a queue if that ever happens
        queue = Queue()

        def flag_concurrent_threads_running():
            # Only called when two threads are running at the same time
            queue.put(True)

        barrier = threading.Barrier(parties=2, action=flag_concurrent_threads_running, timeout=1)

        class PluginImplThatSpawnsMultipleJobs(ScanCommandImplementation):
            @staticmethod
            def _scan_job_work_function(arg1: str) -> str:
                barrier.wait()
                return "ok"

            @classmethod
            def scan_jobs_for_scan_command(
                cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
            ) -> List[ScanJob]:
                return [
                    ScanJob(function_to_call=cls._scan_job_work_function, function_arguments=["test"]) for _ in range(5)
                ]

            @classmethod
            def result_for_completed_scan_jobs(
                cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
            ) -> ScanCommandResult:
                for completed_job in scan_job_results:
                    completed_job.get_result()
                return _MockPluginScanResult(results_field=["ok"])

        with mock.patch.object(
            ScanCommandsRepository, "get_implementation_cls", return_value=PluginImplThatSpawnsMultipleJobs
        ):
            # When running the scan
            scanner.start_scans([server_scan])

            # It succeeds
            all_results = []
            for result in scanner.get_results():
                all_results.append(result)
            assert len(all_results) == 1

            # And there never was more than one thread (=1 job/connection) running at the same time
            assert queue.empty()

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
            assert 1 == len(all_results[0].scan_commands_errors)
            error = all_results[0].scan_commands_errors[0]
            assert error.reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED
