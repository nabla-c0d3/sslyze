import gc
import queue
import warnings
from typing import List, Optional, Generator

from sslyze.scanner._queued_server_scan import ProducerThread, NoMoreServerScansSentinel
from sslyze.scanner.server_scan_request import ServerScanResult, ServerScanRequest


class Scanner:
    def __init__(
        self,
        per_server_concurrent_connections_limit: Optional[int] = None,
        concurrent_server_scans_limit: Optional[int] = None,
    ):
        # Setup default values
        if per_server_concurrent_connections_limit is None:
            final_per_server_concurrent_connections_limit = 5
        else:
            final_per_server_concurrent_connections_limit = per_server_concurrent_connections_limit
        self._per_server_concurrent_connections_count = final_per_server_concurrent_connections_limit

        if concurrent_server_scans_limit is None:
            final_concurrent_server_scans_limit = 10
        else:
            final_concurrent_server_scans_limit = concurrent_server_scans_limit
        self._concurrent_server_scans_count = final_concurrent_server_scans_limit

        self._producer_thread: Optional[ProducerThread] = None  # To be created when we start the scans
        self._server_scan_results_queue: "queue.Queue[ServerScanResult]" = queue.Queue()

        # TODO: Remove in v5.0.0
        self._api_compat_is_enabled = False
        self._api_compat_queued_scans: List[ServerScanRequest] = []

    @property
    def _are_server_scans_ongoing(self) -> bool:
        return True if self._producer_thread else False

    # TODO: Remove in v5.0.0
    def queue_scan(self, server_scan: ServerScanRequest) -> None:
        """Deprecated; use start_server_scans() instead.

        This method is there for backward-compatibility, and will be removed in the next major release.
        """
        warnings.warn("queue_scan() is deprecated, use start_scans() instead", PendingDeprecationWarning)
        self._api_compat_is_enabled = True
        self._api_compat_queued_scans.append(server_scan)

    def start_scans(self, server_scan_requests: List[ServerScanRequest]) -> None:
        if self._are_server_scans_ongoing:
            raise ValueError("Already submitted scan requests")

        self._producer_thread = ProducerThread(
            concurrent_server_scans_count=self._concurrent_server_scans_count,
            per_server_concurrent_connections_count=self._per_server_concurrent_connections_count,
            queued_server_scan_requests=server_scan_requests,
            server_scan_results_queue=self._server_scan_results_queue,
        )
        self._producer_thread.start()

    def get_results(self) -> Generator[ServerScanResult, None, None]:
        # TODO: Remove in v5.0.0
        if self._api_compat_is_enabled:
            self.start_scans(self._api_compat_queued_scans)

        if not self._are_server_scans_ongoing:
            raise ValueError("No scan requests have been submitted")

        while True:
            server_scan_result = self._server_scan_results_queue.get(block=True)
            self._server_scan_results_queue.task_done()
            if isinstance(server_scan_result, NoMoreServerScansSentinel):
                # No more scans to run
                break

            yield server_scan_result
            # Force garbage collection here so that all the objects related to the server scan that completed just now
            # get removed from memory. Without this, SSLyze's memory usage balloons as more scans get queued
            # https://github.com/nabla-c0d3/sslyze/issues/511.
            gc.collect()

        # All done with the scans
        if self._producer_thread is None:
            raise RuntimeError("Should never happen")

        self._server_scan_results_queue.join()
        self._producer_thread.join()
        self._producer_thread = None
        return
