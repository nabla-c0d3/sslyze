import threading
from dataclasses import dataclass
import queue
from typing import Optional, Any, Callable
from uuid import UUID

from sslyze.plugins.scan_commands import ScanCommandType


@dataclass(frozen=True)
class CompletedScanJob:
    for_server_scan_uuid: UUID
    for_scan_command: ScanCommandType

    return_value: Optional[Any]
    exception: Optional[Exception]


@dataclass(frozen=True)
class QueuedScanJob:
    for_server_scan_uuid: UUID
    for_scan_command: ScanCommandType

    function_to_call: Callable
    function_arguments: Any


class WorkerThreadNoMoreJobsSentinel:
    pass


class WorkerThread(threading.Thread):
    def __init__(
        self, incoming_jobs_queue: "queue.Queue[QueuedScanJob]", completed_jobs_queue: "queue.Queue[CompletedScanJob]"
    ):
        super().__init__()
        self._incoming_jobs_queue = incoming_jobs_queue
        self._completed_jobs_queue = completed_jobs_queue
        self.daemon = True  # Shutdown the thread if the program is exiting early (ie. ctrl+c)

    def run(self) -> None:
        while True:
            job_to_complete = self._incoming_jobs_queue.get(block=True)
            if isinstance(job_to_complete, WorkerThreadNoMoreJobsSentinel):
                self._incoming_jobs_queue.task_done()
                # No more jobs to complete - shutdown the thread
                break

            try:
                return_value = job_to_complete.function_to_call(*job_to_complete.function_arguments)
                self._completed_jobs_queue.put(
                    CompletedScanJob(
                        for_server_scan_uuid=job_to_complete.for_server_scan_uuid,
                        for_scan_command=job_to_complete.for_scan_command,
                        return_value=return_value,
                        exception=None,
                    )
                )
            except Exception as e:
                self._completed_jobs_queue.put(
                    CompletedScanJob(
                        for_server_scan_uuid=job_to_complete.for_server_scan_uuid,
                        for_scan_command=job_to_complete.for_scan_command,
                        return_value=None,
                        exception=e,
                    )
                )
            self._incoming_jobs_queue.task_done()
