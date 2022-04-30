import threading
from pathlib import Path
from queue import Queue
from typing import Optional, List
from unittest import mock

from sslyze import (
    ScanCommand,
    ServerConnectivityStatusEnum,
    ServerScanStatusEnum,
    ScanCommandAttemptStatusEnum,
    ScanCommandsExtraArguments,
    CertificateInfoExtraArgument,
    ScanCommandErrorReasonEnum,
)
from sslyze.errors import TlsHandshakeTimedOut
from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandExtraArgument,
    ScanJob,
    ScanCommandResult,
    ScanJobResult,
)
from sslyze.plugins.scan_commands import ScanCommandsRepository
from sslyze.scanner._mass_scanner import MassScannerProducerThread, NoMoreServerScanRequestsSentinel
from sslyze.server_connectivity import ServerConnectivityInfo
from tests.factories import ServerScanRequestFactory, ServerTlsProbingResultFactory

from tests.scanner_tests.conftest import MockPluginScanResult


class TestMassScannerProducerThread:
    def test(self, mock_scan_commands):
        # Given a MassScanner thread that's ready to process server scan requests
        server_scan_requests_queue_in = Queue()
        server_scan_results_queue_out = Queue()
        mass_scanner_thread = MassScannerProducerThread(
            concurrent_server_scans_count=5,
            per_server_concurrent_connections_count=5,
            server_scan_requests_queue_in=server_scan_requests_queue_in,
            server_scan_results_queue_out=server_scan_results_queue_out,
        )
        mass_scanner_thread.start()

        # And a bunch of servers to scan
        all_server_scan_requests_and_connectivity_results = []
        scan_commands_to_run = {ScanCommand.CERTIFICATE_INFO, ScanCommand.ROBOT, ScanCommand.TLS_COMPRESSION}
        for _ in range(20):
            scan_request = ServerScanRequestFactory.create(scan_commands=scan_commands_to_run)
            connectivity_result = ServerTlsProbingResultFactory.create()
            all_server_scan_requests_and_connectivity_results.append((scan_request, connectivity_result))

        # When queuing the scans
        for req_and_connectivity_result in all_server_scan_requests_and_connectivity_results:
            server_scan_requests_queue_in.put(req_and_connectivity_result)
        server_scan_requests_queue_in.put(NoMoreServerScanRequestsSentinel())

        # Then the scans were performed
        all_server_scan_results = []
        while True:
            result = server_scan_results_queue_out.get(block=True)
            server_scan_results_queue_out.task_done()
            if isinstance(result, NoMoreServerScanRequestsSentinel):
                break
            all_server_scan_results.append(result)

        # And the right results were returned
        assert len(all_server_scan_results) == len(all_server_scan_requests_and_connectivity_results)
        for server_scan_result in all_server_scan_results:
            assert server_scan_result.connectivity_status == ServerConnectivityStatusEnum.COMPLETED
            assert server_scan_result.connectivity_error_trace is None
            assert server_scan_result.connectivity_result
            assert server_scan_result.scan_status == ServerScanStatusEnum.COMPLETED

            # Including the results of individual scan commands
            assert server_scan_result.scan_result
            assert server_scan_result.scan_result.certificate_info.status == ScanCommandAttemptStatusEnum.COMPLETED
            assert server_scan_result.scan_result.certificate_info.result
            assert server_scan_result.scan_result.robot.status == ScanCommandAttemptStatusEnum.COMPLETED
            assert server_scan_result.scan_result.robot.result
            assert server_scan_result.scan_result.tls_compression.status == ScanCommandAttemptStatusEnum.COMPLETED
            assert server_scan_result.scan_result.tls_compression.result
            assert server_scan_result.scan_result.heartbleed.status == ScanCommandAttemptStatusEnum.NOT_SCHEDULED
            assert server_scan_result.scan_result.heartbleed.result is None

        # And the threads and queues were shutdown cleanly
        server_scan_requests_queue_in.join()
        server_scan_results_queue_out.join()

        mass_scanner_thread._completed_jobs_queue.join()
        for worker_queue in mass_scanner_thread._all_worker_queues:
            worker_queue.join()

        for worker_thread in mass_scanner_thread._all_worker_threads:
            worker_thread.join()
        mass_scanner_thread.join()

    def test_with_extra_arguments(self, mock_scan_commands):
        # Given a MassScanner thread that's ready to process server scan requests
        server_scan_requests_queue_in = Queue()
        server_scan_results_queue_out = Queue()
        mass_scanner_thread = MassScannerProducerThread(
            concurrent_server_scans_count=5,
            per_server_concurrent_connections_count=5,
            server_scan_requests_queue_in=server_scan_requests_queue_in,
            server_scan_results_queue_out=server_scan_results_queue_out,
        )
        mass_scanner_thread.start()

        # And a server to scan with a scan command that takes an extra argument
        scan_commands_extra_arguments = ScanCommandsExtraArguments(
            certificate_info=CertificateInfoExtraArgument(custom_ca_file=Path(__file__))
        )
        server_scan_request = ServerScanRequestFactory.create(
            scan_commands={ScanCommand.CERTIFICATE_INFO},
            scan_commands_extra_arguments=scan_commands_extra_arguments,
        )
        server_connectivity_result = ServerTlsProbingResultFactory.create()

        # When queuing the scan
        server_scan_requests_queue_in.put((server_scan_request, server_connectivity_result))
        server_scan_requests_queue_in.put(NoMoreServerScanRequestsSentinel())

        # Then the scan was performed
        all_server_scan_results = []
        while True:
            result = server_scan_results_queue_out.get(block=True)
            server_scan_results_queue_out.task_done()
            if isinstance(result, NoMoreServerScanRequestsSentinel):
                break
            all_server_scan_results.append(result)

        # And the right result was returned
        assert len(all_server_scan_results) == 1

        # And the extra argument was taken into account
        assert all_server_scan_results[0].scan_result.certificate_info.result.did_receive_extra_arguments

    def test_error_bug_in_sslyze_when_scheduling_jobs(self):
        # Given a MassScanner thread that's ready to process server scan requests
        server_scan_requests_queue_in = Queue()
        server_scan_results_queue_out = Queue()
        mass_scanner_thread = MassScannerProducerThread(
            concurrent_server_scans_count=5,
            per_server_concurrent_connections_count=5,
            server_scan_requests_queue_in=server_scan_requests_queue_in,
            server_scan_results_queue_out=server_scan_results_queue_out,
        )
        mass_scanner_thread.start()

        # And a server to scan with a scan command
        server_scan_request = ServerScanRequestFactory.create(scan_commands={ScanCommand.CERTIFICATE_INFO})
        server_connectivity_result = ServerTlsProbingResultFactory.create()

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
            # When queuing the scan
            server_scan_requests_queue_in.put((server_scan_request, server_connectivity_result))
            server_scan_requests_queue_in.put(NoMoreServerScanRequestsSentinel())

            # Then the scan was performed
            all_server_scan_results = []
            while True:
                result = server_scan_results_queue_out.get(block=True)
                server_scan_results_queue_out.task_done()
                if isinstance(result, NoMoreServerScanRequestsSentinel):
                    break
                all_server_scan_results.append(result)

            # And the right result was returned
            assert len(all_server_scan_results) == 1
            scan_command_result = all_server_scan_results[0].scan_result.certificate_info

            # And the exception was properly caught and returned
            assert scan_command_result.status == ScanCommandAttemptStatusEnum.ERROR
            assert scan_command_result.error_reason == ScanCommandErrorReasonEnum.BUG_IN_SSLYZE
            assert scan_command_result.error_trace
            assert scan_command_result.result is None

    def test_error_bug_in_sslyze_when_processing_job_results(self):
        # Given a MassScanner thread that's ready to process server scan requests
        server_scan_requests_queue_in = Queue()
        server_scan_results_queue_out = Queue()
        mass_scanner_thread = MassScannerProducerThread(
            concurrent_server_scans_count=5,
            per_server_concurrent_connections_count=5,
            server_scan_requests_queue_in=server_scan_requests_queue_in,
            server_scan_results_queue_out=server_scan_results_queue_out,
        )
        mass_scanner_thread.start()

        # And a server to scan with a scan command
        server_scan_request = ServerScanRequestFactory.create(scan_commands={ScanCommand.CERTIFICATE_INFO})
        server_connectivity_result = ServerTlsProbingResultFactory.create()

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
            # When queuing the scan
            server_scan_requests_queue_in.put((server_scan_request, server_connectivity_result))
            server_scan_requests_queue_in.put(NoMoreServerScanRequestsSentinel())

            # Then the scan was performed
            all_server_scan_results = []
            while True:
                result = server_scan_results_queue_out.get(block=True)
                server_scan_results_queue_out.task_done()
                if isinstance(result, NoMoreServerScanRequestsSentinel):
                    break
                all_server_scan_results.append(result)

            # And the right result was returned
            assert len(all_server_scan_results) == 1
            scan_command_result = all_server_scan_results[0].scan_result.certificate_info

            # And the exception was properly caught and returned
            assert scan_command_result.status == ScanCommandAttemptStatusEnum.ERROR
            assert scan_command_result.error_reason == ScanCommandErrorReasonEnum.BUG_IN_SSLYZE
            assert scan_command_result.error_trace
            assert scan_command_result.result is None

    def test_error_server_connectivity_issue_handshake_timeout(self):
        # Given a MassScanner thread that's ready to process server scan requests
        server_scan_requests_queue_in = Queue()
        server_scan_results_queue_out = Queue()
        mass_scanner_thread = MassScannerProducerThread(
            concurrent_server_scans_count=5,
            per_server_concurrent_connections_count=5,
            server_scan_requests_queue_in=server_scan_requests_queue_in,
            server_scan_results_queue_out=server_scan_results_queue_out,
        )
        mass_scanner_thread.start()

        # And a server to scan with a scan command
        server_scan_request = ServerScanRequestFactory.create(scan_commands={ScanCommand.CERTIFICATE_INFO})
        server_connectivity_result = ServerTlsProbingResultFactory.create()

        # And the scan command will trigger a connectivity error when doing work
        class PluginImplThatTriggersConnectivityError(ScanCommandImplementation):
            @staticmethod
            def _scan_job_work_function(arg1: str) -> str:
                raise TlsHandshakeTimedOut(
                    server_location=server_scan_request.server_location,
                    network_configuration=server_scan_request.network_configuration,
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
                    # This will trigger the exception from _scan_job_work_function()
                    completed_job.get_result()
                return MockPluginScanResult(results_field=["ok"])

        with mock.patch.object(
            ScanCommandsRepository, "get_implementation_cls", return_value=PluginImplThatTriggersConnectivityError
        ):
            # When queuing the scan
            server_scan_requests_queue_in.put((server_scan_request, server_connectivity_result))
            server_scan_requests_queue_in.put(NoMoreServerScanRequestsSentinel())

            # Then the scan was performed
            all_server_scan_results = []
            while True:
                result = server_scan_results_queue_out.get(block=True)
                server_scan_results_queue_out.task_done()
                if isinstance(result, NoMoreServerScanRequestsSentinel):
                    break
                all_server_scan_results.append(result)

            # And the right result was returned
            assert len(all_server_scan_results) == 1
            scan_command_result = all_server_scan_results[0].scan_result.certificate_info

            # And the exception was properly caught and returned
            assert scan_command_result.status == ScanCommandAttemptStatusEnum.ERROR
            assert scan_command_result.error_reason == ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE
            assert scan_command_result.error_trace
            assert scan_command_result.result is None

    def test_enforces_per_server_concurrent_connections_limit(self):
        # Given a MassScanner thread that's ready to process server scan requests
        server_scan_requests_queue_in = Queue()
        server_scan_results_queue_out = Queue()
        mass_scanner_thread = MassScannerProducerThread(
            concurrent_server_scans_count=5,
            # And that is configured to only perform two concurrent connections/jobs per server scan
            per_server_concurrent_connections_count=2,
            server_scan_requests_queue_in=server_scan_requests_queue_in,
            server_scan_results_queue_out=server_scan_results_queue_out,
        )
        mass_scanner_thread.start()

        # And a server to scan with a scan command
        server_scan_request = ServerScanRequestFactory.create(scan_commands={ScanCommand.CERTIFICATE_INFO})
        server_connectivity_result = ServerTlsProbingResultFactory.create()

        # And the scan scan command requires multiple connections/jobs to the server
        # And the scan command will notify us when more than 2 and more than 3 jobs are being performed concurrently
        # We use a Barrier that waits for 2 concurrent threads, and puts True in a queue if that ever happens
        # And another Barrier that does the same thing for 3 concurrent threads
        queue_for_two_concurrent_jobs = Queue()
        queue_for_three_concurrent_jobs = Queue()

        def flag_two_concurrent_jobs_running():
            queue_for_two_concurrent_jobs.put(True)

        def flag_three_concurrent_jobs_running():
            queue_for_three_concurrent_jobs.put(True)

        barrier_two_jobs = threading.Barrier(parties=2, action=flag_two_concurrent_jobs_running, timeout=1)
        barrier_three_jobs = threading.Barrier(parties=3, action=flag_three_concurrent_jobs_running, timeout=1)

        class PluginImplThatSpawnsMultipleJobs(ScanCommandImplementation):
            @staticmethod
            def _job_work_function(arg1: str) -> str:
                try:
                    barrier_two_jobs.wait()
                    barrier_three_jobs.wait()
                except threading.BrokenBarrierError:
                    pass
                return "ok"

            @classmethod
            def scan_jobs_for_scan_command(
                cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
            ) -> List[ScanJob]:
                return [
                    ScanJob(function_to_call=cls._job_work_function, function_arguments=["test"]) for _ in range(10)
                ]

            @classmethod
            def result_for_completed_scan_jobs(
                cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
            ) -> ScanCommandResult:
                for completed_job in scan_job_results:
                    completed_job.get_result()
                return MockPluginScanResult(results_field=["ok"])

        with mock.patch.object(
            ScanCommandsRepository, "get_implementation_cls", return_value=PluginImplThatSpawnsMultipleJobs
        ):
            # When queuing the scan
            server_scan_requests_queue_in.put((server_scan_request, server_connectivity_result))
            server_scan_requests_queue_in.put(NoMoreServerScanRequestsSentinel())

            # Then the scan was performed
            all_server_scan_results = []
            while True:
                result = server_scan_results_queue_out.get(block=True)
                server_scan_results_queue_out.task_done()
                if isinstance(result, NoMoreServerScanRequestsSentinel):
                    break
                all_server_scan_results.append(result)

            # And the right result was returned
            assert len(all_server_scan_results) == 1
            certificate_info_status = all_server_scan_results[0].scan_result.certificate_info.status
            assert certificate_info_status == ScanCommandAttemptStatusEnum.COMPLETED

            # And there were 2 threads/jobs running at the same time
            assert not queue_for_two_concurrent_jobs.empty()

            # But never 3 threads/jobs at the same time due to per_server_concurrent_connections_count==2
            assert queue_for_three_concurrent_jobs.empty()
