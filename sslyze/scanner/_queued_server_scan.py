import threading
from dataclasses import dataclass
import queue
from time import sleep
from traceback import TracebackException
from typing import Dict, List, Tuple
from uuid import UUID, uuid4

from nassl.ssl_client import ClientCertificateRequested

from sslyze.errors import ConnectionToServerTimedOut, TlsHandshakeTimedOut
from sslyze.plugins.plugin_base import ScanCommandWrongUsageError, ScanJob, ScanJobResult, ScanCommandResult
from sslyze.plugins.scan_commands import ScanCommandsRepository, ScanCommand
from sslyze.scanner._worker_thread import WorkerThreadNoMoreJobsSentinel, CompletedScanJob, QueuedScanJob, WorkerThread
from sslyze.scanner.server_scan_request import (
    ServerScanRequest,
    ServerScanResult,
    ScanCommandError,
    ScanCommandErrorReasonEnum,
    ScanCommandsResults,
)


@dataclass(frozen=True)
class _QueuedServerScan:
    uuid: UUID
    server_scan_request: ServerScanRequest
    scan_command_errors_during_queuing: List[ScanCommandError]
    assigned_queue: queue.Queue
    queued_scan_jobs_count: int
    completed_scan_jobs: List[CompletedScanJob]  # Populated as the scan is getting completed

    @property
    def is_completed(self) -> bool:
        return self.queued_scan_jobs_count == len(self.completed_scan_jobs)


class NoMoreServerScansSentinel:
    pass


class ProducerThread(threading.Thread):
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
        queued_server_scan_requests: List[ServerScanRequest],
        server_scan_results_queue: "queue.Queue[ServerScanResult]",
    ):
        super().__init__()
        self._server_scan_results_queue = server_scan_results_queue
        self._queued_server_scan_requests = queued_server_scan_requests
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
                    WorkerThread(incoming_jobs_queue=worker_queue, completed_jobs_queue=self._completed_jobs_queue)
                    for _ in range(self._worker_threads_per_queues_count)
                ]
            )
        for worker_thread in self._all_worker_threads:
            worker_thread.start()

    def run(self) -> None:
        # Start the first batch of scans
        all_ongoing_server_scans: Dict[UUID, _QueuedServerScan] = {}
        for worker_queue in self._all_worker_queues:
            # Dispatch one server scan per available queue
            try:
                next_server_scan_request = self._queued_server_scan_requests.pop()
            except IndexError:
                # No more server scans
                break
            else:
                next_queued_server_scan = _queue_server_scan(next_server_scan_request, worker_queue)
                all_ongoing_server_scans[next_queued_server_scan.uuid] = next_queued_server_scan

        # Main loop for checking if a server scan was completed and queuing the next scan
        while all_ongoing_server_scans:
            # Wait for some jobs to complete
            sleep(0.2)

            # Retrieve and store completed jobs
            while not self._completed_jobs_queue.empty():
                completed_job = self._completed_jobs_queue.get(block=False)
                parent_server_scan = all_ongoing_server_scans[completed_job.for_server_scan_uuid]
                parent_server_scan.completed_scan_jobs.append(completed_job)
                self._completed_jobs_queue.task_done()

            # Check if any server scan has been fully completed
            all_completed_server_scans = []
            for ongoing_server_scan in all_ongoing_server_scans.values():
                if ongoing_server_scan.is_completed:
                    all_completed_server_scans.append(ongoing_server_scan)

            for completed_server_scan in all_completed_server_scans:
                # All done with this scan: generate and send the results
                del all_ongoing_server_scans[completed_server_scan.uuid]
                server_scan_result = _generate_result_for_completed_server_scan(completed_server_scan)
                self._server_scan_results_queue.put(server_scan_result)

                # Then start the next server scan on the same queue
                try:
                    next_server_scan_request = self._queued_server_scan_requests.pop()
                except IndexError:
                    # No more server scans
                    pass
                else:
                    next_queued_server_scan = _queue_server_scan(
                        next_server_scan_request, completed_server_scan.assigned_queue
                    )
                    all_ongoing_server_scans[next_queued_server_scan.uuid] = next_queued_server_scan

        # If we get here there are no more ongoing server scans; we are all done
        # Shutdown the worker queue and threads
        self._completed_jobs_queue.join()
        for worker_queue in self._all_worker_queues:
            for _ in range(self._worker_threads_per_queues_count):
                worker_queue.put(WorkerThreadNoMoreJobsSentinel())  # type: ignore
                worker_queue.join()

        for worker_thread in self._all_worker_threads:
            worker_thread.join()

        self._server_scan_results_queue.put(NoMoreServerScansSentinel())  # type: ignore
        self._server_scan_results_queue.join()


def _queue_server_scan(
    server_scan_request: ServerScanRequest, assigned_worker_queue: "queue.Queue[QueuedScanJob]"
) -> _QueuedServerScan:
    # Queue all the underlying jobs for this server scan
    all_scan_jobs_per_scan_cmd, scan_command_errors_during_queuing = _generate_scan_jobs_for_server_scan(
        server_scan_request
    )
    total_job_counts = 0
    queued_server_scan_uuid = uuid4()
    for scan_cmd, all_jobs in all_scan_jobs_per_scan_cmd.items():
        for job in all_jobs:
            total_job_counts += 1
            assigned_worker_queue.put(
                QueuedScanJob(
                    for_server_scan_uuid=queued_server_scan_uuid,
                    for_scan_command=scan_cmd,
                    function_to_call=job.function_to_call,
                    function_arguments=job.function_arguments,
                )
            )

    # Return information about the server scan that was just queued
    queued_server_scan = _QueuedServerScan(
        uuid=queued_server_scan_uuid,
        server_scan_request=server_scan_request,
        assigned_queue=assigned_worker_queue,
        scan_command_errors_during_queuing=scan_command_errors_during_queuing,
        queued_scan_jobs_count=total_job_counts,
        completed_scan_jobs=[],
    )
    return queued_server_scan


def _generate_scan_jobs_for_server_scan(
    server_scan_request: ServerScanRequest,
) -> Tuple[Dict[ScanCommand, List[ScanJob]], List[ScanCommandError]]:
    all_scan_jobs_per_scan_cmd: Dict[ScanCommand, List[ScanJob]] = {}
    scan_command_errors_during_queuing: List[ScanCommandError] = []
    for scan_cmd in server_scan_request.scan_commands:
        implementation_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd)
        scan_cmd_extra_args = getattr(server_scan_request.scan_commands_extra_arguments, scan_cmd, None)

        try:
            jobs_for_scan_cmd = implementation_cls.scan_jobs_for_scan_command(
                server_info=server_scan_request.server_info, extra_arguments=scan_cmd_extra_args
            )
            all_scan_jobs_per_scan_cmd[scan_cmd] = jobs_for_scan_cmd
        # Process exceptions and instantly "complete" the scan command if the call to create the jobs failed
        except ScanCommandWrongUsageError as e:
            error = ScanCommandError(
                scan_command=scan_cmd,
                reason=ScanCommandErrorReasonEnum.WRONG_USAGE,
                exception_trace=TracebackException.from_exception(e),
            )
            scan_command_errors_during_queuing.append(error)
        except Exception as e:
            error = ScanCommandError(
                scan_command=scan_cmd,
                reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                exception_trace=TracebackException.from_exception(e),
            )
            scan_command_errors_during_queuing.append(error)

    return all_scan_jobs_per_scan_cmd, scan_command_errors_during_queuing


def _generate_result_for_completed_server_scan(completed_scan: _QueuedServerScan) -> ServerScanResult:
    server_scan_results: Dict[ScanCommand, ScanCommandResult] = {}
    server_scan_errors: List[ScanCommandError] = []

    # Group all the completed jobs per scan command
    scan_cmd_to_completed_jobs: Dict[ScanCommand, List[CompletedScanJob]] = {
        scan_cmd: [] for scan_cmd in completed_scan.server_scan_request.scan_commands
    }
    for completed_job in completed_scan.completed_scan_jobs:
        scan_cmd_to_completed_jobs[completed_job.for_scan_command].append(completed_job)

    for scan_cmd, completed_scan_jobs in scan_cmd_to_completed_jobs.items():
        # Pass the completed scan jobs to the corresponding plugin implementation to generate a result
        scan_job_results_for_plugin = [
            ScanJobResult(_return_value=job.return_value, _exception=job.exception) for job in completed_scan_jobs
        ]
        server_info = completed_scan.server_scan_request.server_info
        plugin_implementation_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd)
        try:
            result = plugin_implementation_cls.result_for_completed_scan_jobs(server_info, scan_job_results_for_plugin)
            server_scan_results[scan_cmd] = result

        # Process exceptions that may have been raised while the jobs were being completed
        except ClientCertificateRequested as e:
            error = ScanCommandError(
                scan_command=scan_cmd,
                reason=ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED,
                exception_trace=TracebackException.from_exception(e),
            )
            server_scan_errors.append(error)
        except (ConnectionToServerTimedOut, TlsHandshakeTimedOut) as e:
            error = ScanCommandError(
                scan_command=scan_cmd,
                reason=ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE,
                exception_trace=TracebackException.from_exception(e),
            )
            server_scan_errors.append(error)
        except Exception as e:
            error = ScanCommandError(
                scan_command=scan_cmd,
                reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                exception_trace=TracebackException.from_exception(e),
            )
            server_scan_errors.append(error)

    # Lastly, return the fully completed server scan
    server_scan_errors.extend(completed_scan.scan_command_errors_during_queuing)
    server_scan_result = ServerScanResult(
        scan_commands_results=ScanCommandsResults(**server_scan_results),  # type: ignore
        scan_commands_errors=server_scan_errors,
        server_info=completed_scan.server_scan_request.server_info,
        scan_commands=completed_scan.server_scan_request.scan_commands,
        scan_commands_extra_arguments=completed_scan.server_scan_request.scan_commands_extra_arguments,
    )
    return server_scan_result
