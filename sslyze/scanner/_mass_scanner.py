import threading
from dataclasses import dataclass, fields
import queue
from time import sleep
from traceback import TracebackException
from typing import Dict, List, Tuple
from uuid import UUID

from nassl.ssl_client import ClientCertificateRequested

from sslyze import ServerTlsProbingResult, ScanCommandAttemptStatusEnum, ScanCommandErrorReasonEnum
from sslyze.errors import ConnectionToServerTimedOut, TlsHandshakeTimedOut, ServerRejectedTlsHandshake
from sslyze.plugins.plugin_base import ScanCommandWrongUsageError, ScanJob, ScanJobResult
from sslyze.plugins.scan_commands import ScanCommandsRepository, ScanCommand
from sslyze.scanner._jobs_worker_thread import (
    WorkerThreadNoMoreJobsSentinel,
    CompletedScanJob,
    QueuedScanJob,
    JobsWorkerThread,
)
from sslyze.scanner.models import (
    ServerScanRequest,
    ServerScanResult,
    ServerConnectivityStatusEnum,
    ServerScanStatusEnum,
    AllScanCommandsAttempts,
    get_scan_command_attempt_cls,
)
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class _OngoingServerScan:
    server_scan_request: ServerScanRequest
    server_connectivity_result: ServerTlsProbingResult
    assigned_queue: queue.Queue
    scan_command_errors_during_queuing: Dict[ScanCommand, ScanCommandAttempt]
    queued_scan_jobs_count: int
    completed_scan_jobs: List[CompletedScanJob]  # Populated as the scan is getting completed

    @property
    def is_completed(self) -> bool:
        return self.queued_scan_jobs_count == len(self.completed_scan_jobs)


class NoMoreServerScanRequestsSentinel:
    pass


class MassScannerProducerThread(threading.Thread):
    """Thread to continuously process more scans and the corresponding jobs as previous ones get completed.

    The goal is to reduce memory usage, by only generating objects related to a single server scan (ScanJob, etc.) when
    the scan is ongoing, instead of generating all objects for all scans at the very beginning.
    The previous implementation used ThreadPoolExecutor and took a lot memory because it did just that:
    https://github.com/nabla-c0d3/sslyze/issues/511
    """

    def __init__(
        self,
        concurrent_server_scans_count: int,
        per_server_concurrent_connections_count: int,
        server_scan_requests_queue_in: "queue.Queue[Tuple[ServerScanRequest, ServerTlsProbingResult]]",
        server_scan_results_queue_out: "queue.Queue[ServerScanResult]",
    ):
        super().__init__()
        self._server_scan_results_queue_out = server_scan_results_queue_out
        self._server_scan_requests_queue_in = server_scan_requests_queue_in
        self.daemon = True  # Shutdown the thread if the program is exiting early (ie. ctrl+c)

        # Create internal threads and queues for dispatching jobs
        self._completed_jobs_queue: "queue.Queue[CompletedScanJob]" = queue.Queue()
        self._all_worker_queues: List["queue.Queue[QueuedScanJob]"] = [
            queue.Queue() for _ in range(concurrent_server_scans_count)
        ]
        self._worker_threads_per_queues_count = per_server_concurrent_connections_count
        self._all_worker_threads = []
        for worker_queue in self._all_worker_queues:
            self._all_worker_threads.extend(
                [
                    JobsWorkerThread(jobs_queue_in=worker_queue, completed_jobs_queue_out=self._completed_jobs_queue)
                    for _ in range(self._worker_threads_per_queues_count)
                ]
            )
        for worker_thread in self._all_worker_threads:
            worker_thread.start()

    def run(self) -> None:
        all_ongoing_server_scans: Dict[UUID, _OngoingServerScan] = {}

        # Start the first batch of scans; dispatch one server scan per available queue
        has_retrieved_all_server_scan_requests = False
        for worker_queue in self._all_worker_queues:
            entry_in_queue = self._server_scan_requests_queue_in.get(block=True)
            if isinstance(entry_in_queue, NoMoreServerScanRequestsSentinel):
                has_retrieved_all_server_scan_requests = True
                self._server_scan_requests_queue_in.task_done()
                break

            server_scan_request, server_connectivity_result = entry_in_queue
            next_queued_server_scan = _queue_server_scan(
                server_scan_request=server_scan_request,
                server_connectivity_result=server_connectivity_result,
                assigned_worker_queue=worker_queue,
            )
            all_ongoing_server_scans[server_scan_request.uuid] = next_queued_server_scan
            self._server_scan_requests_queue_in.task_done()

        # Main loop for checking if a server scan was completed and queuing the next scan
        while all_ongoing_server_scans:
            # Wait for some jobs to complete
            sleep(0.2)

            # Retrieve and store completed jobs
            while not self._completed_jobs_queue.empty():
                completed_job = self._completed_jobs_queue.get(block=False)
                parent_server_scan = all_ongoing_server_scans[completed_job.parent_server_scan_request_uuid]
                parent_server_scan.completed_scan_jobs.append(completed_job)
                self._completed_jobs_queue.task_done()

            # Check if any server scan has been fully completed
            all_completed_server_scans = []
            for ongoing_server_scan in all_ongoing_server_scans.values():
                if ongoing_server_scan.is_completed:
                    all_completed_server_scans.append(ongoing_server_scan)

            # For fully completed scans, send back the results
            for completed_server_scan in all_completed_server_scans:
                del all_ongoing_server_scans[completed_server_scan.server_scan_request.uuid]
                server_scan_result = _generate_result_for_completed_server_scan(completed_server_scan)
                self._server_scan_results_queue_out.put(server_scan_result)

                # After sending the result, start the next server scan on the same queue
                if has_retrieved_all_server_scan_requests:
                    # But do nothing if all the scans have already been queued
                    continue

                entry_in_queue = self._server_scan_requests_queue_in.get(block=True)
                if isinstance(entry_in_queue, NoMoreServerScanRequestsSentinel):
                    # No more server scans
                    has_retrieved_all_server_scan_requests = True
                    self._server_scan_requests_queue_in.task_done()
                else:
                    server_scan_request, server_connectivity_result = entry_in_queue
                    next_queued_server_scan = _queue_server_scan(
                        server_scan_request=server_scan_request,
                        server_connectivity_result=server_connectivity_result,
                        assigned_worker_queue=completed_server_scan.assigned_queue,
                    )
                    all_ongoing_server_scans[server_scan_request.uuid] = next_queued_server_scan
                    self._server_scan_requests_queue_in.task_done()

        # If we get here there are no more ongoing server scans; we are all done
        # Shutdown the worker queue and threads
        self._completed_jobs_queue.join()
        for worker_queue in self._all_worker_queues:
            for _ in range(self._worker_threads_per_queues_count):
                worker_queue.put(WorkerThreadNoMoreJobsSentinel())  # type: ignore
                worker_queue.join()

        for worker_thread in self._all_worker_threads:
            worker_thread.join()

        self._server_scan_results_queue_out.put(NoMoreServerScanRequestsSentinel())  # type: ignore
        self._server_scan_results_queue_out.join()


def _queue_server_scan(
    server_scan_request: ServerScanRequest,
    server_connectivity_result: ServerTlsProbingResult,
    assigned_worker_queue: "queue.Queue[QueuedScanJob]",
) -> _OngoingServerScan:
    # Queue all the underlying jobs for this server scan
    all_scan_jobs_per_scan_cmd, scan_command_errors_during_queuing = _generate_scan_jobs_for_server_scan(
        server_scan_request=server_scan_request,
        server_connectivity_result=server_connectivity_result,
    )
    total_job_counts = 0
    for scan_cmd, all_jobs in all_scan_jobs_per_scan_cmd.items():
        for job in all_jobs:
            total_job_counts += 1
            assigned_worker_queue.put(
                QueuedScanJob(
                    parent_server_scan_request_uuid=server_scan_request.uuid,
                    for_scan_command=scan_cmd,
                    function_to_call=job.function_to_call,
                    function_arguments=job.function_arguments,
                )
            )

    # Return information about the server scan that was just queued
    queued_server_scan = _OngoingServerScan(
        server_scan_request=server_scan_request,
        server_connectivity_result=server_connectivity_result,
        assigned_queue=assigned_worker_queue,
        scan_command_errors_during_queuing=scan_command_errors_during_queuing,
        queued_scan_jobs_count=total_job_counts,
        completed_scan_jobs=[],
    )
    return queued_server_scan


def _generate_scan_jobs_for_server_scan(
    server_scan_request: ServerScanRequest,
    server_connectivity_result: ServerTlsProbingResult,
) -> Tuple[Dict[ScanCommand, List[ScanJob]], Dict[ScanCommand, ScanCommandAttempt]]:
    all_scan_jobs_per_scan_cmd: Dict[ScanCommand, List[ScanJob]] = {}
    scan_command_errors_during_queuing: Dict[ScanCommand, ScanCommandAttempt] = {}
    for scan_cmd in server_scan_request.scan_commands:
        implementation_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd)
        scan_cmd_extra_args = getattr(server_scan_request.scan_commands_extra_arguments, scan_cmd, None)

        try:
            jobs_for_scan_cmd = implementation_cls.scan_jobs_for_scan_command(
                server_info=ServerConnectivityInfo(
                    server_location=server_scan_request.server_location,
                    network_configuration=server_scan_request.network_configuration,
                    tls_probing_result=server_connectivity_result,
                ),
                extra_arguments=scan_cmd_extra_args,
            )
            all_scan_jobs_per_scan_cmd[scan_cmd] = jobs_for_scan_cmd

        # Process exceptions and instantly "complete" the scan command if the call to create the jobs failed
        except ScanCommandWrongUsageError as e:
            scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)
            errored_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.WRONG_USAGE,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )
            scan_command_errors_during_queuing[scan_cmd] = errored_attempt
        except Exception as e:
            scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)
            errored_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )
            scan_command_errors_during_queuing[scan_cmd] = errored_attempt

    return all_scan_jobs_per_scan_cmd, scan_command_errors_during_queuing


def _generate_result_for_completed_server_scan(completed_scan: _OngoingServerScan) -> ServerScanResult:
    all_scan_command_attempts: Dict[ScanCommand, ScanCommandAttempt] = {}

    # Group all the completed jobs per scan command
    scan_cmd_to_completed_jobs: Dict[ScanCommand, List[CompletedScanJob]] = {
        scan_cmd: [] for scan_cmd in completed_scan.server_scan_request.scan_commands
    }
    for completed_job in completed_scan.completed_scan_jobs:
        scan_cmd_to_completed_jobs[completed_job.for_scan_command].append(completed_job)

    for scan_cmd, completed_scan_jobs in scan_cmd_to_completed_jobs.items():
        scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)

        # Pass the completed scan jobs to the corresponding plugin implementation to generate a result
        scan_job_results_for_plugin = [
            ScanJobResult(_return_value=job.return_value, _exception=job.exception) for job in completed_scan_jobs
        ]
        plugin_implementation_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd)
        try:
            scan_cmd_result = plugin_implementation_cls.result_for_completed_scan_jobs(
                server_info=ServerConnectivityInfo(
                    server_location=completed_scan.server_scan_request.server_location,
                    network_configuration=completed_scan.server_scan_request.network_configuration,
                    tls_probing_result=completed_scan.server_connectivity_result,
                ),
                scan_job_results=scan_job_results_for_plugin,
            )
            scan_cmd_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.COMPLETED,
                error_reason=None,
                error_trace=None,
                result=scan_cmd_result,
            )

        # Process exceptions that may have been raised while the jobs were being completed
        except ClientCertificateRequested as e:
            scan_cmd_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )
        except (ConnectionToServerTimedOut, TlsHandshakeTimedOut, ServerRejectedTlsHandshake) as e:
            scan_cmd_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )
        except Exception as e:
            scan_cmd_attempt = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.ERROR,
                error_reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                error_trace=TracebackException.from_exception(e),
                result=None,
            )

        all_scan_command_attempts[scan_cmd] = scan_cmd_attempt

    # Add scan command attempts that failed when queuing them
    all_scan_command_attempts.update(completed_scan.scan_command_errors_during_queuing)

    # Add remaining scan commands as NOT_SCHEDULED
    for cls_field in fields(AllScanCommandsAttempts):
        if cls_field.name not in all_scan_command_attempts:
            scan_cmd = ScanCommand(cls_field.name)
            scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)
            all_scan_command_attempts[scan_cmd] = scan_command_attempt_cls(
                status=ScanCommandAttemptStatusEnum.NOT_SCHEDULED,
                error_reason=None,
                error_trace=None,
                result=None,
            )

    # Generate the final scan_result object
    scan_cmd_str_to_scan_cmd_result = {
        scan_cmd.value: scan_cmd_result for scan_cmd, scan_cmd_result in all_scan_command_attempts.items()
    }
    scan_result = AllScanCommandsAttempts(**scan_cmd_str_to_scan_cmd_result)  # type: ignore

    # Lastly, return the fully completed server scan
    server_scan_result = ServerScanResult(
        uuid=completed_scan.server_scan_request.uuid,
        server_location=completed_scan.server_scan_request.server_location,
        network_configuration=completed_scan.server_scan_request.network_configuration,
        connectivity_status=ServerConnectivityStatusEnum.COMPLETED,
        connectivity_error_trace=None,
        connectivity_result=completed_scan.server_connectivity_result,
        scan_status=ServerScanStatusEnum.COMPLETED,
        scan_result=scan_result,
    )
    return server_scan_result
