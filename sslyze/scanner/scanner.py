import queue
from traceback import TracebackException
from typing import List, Optional, Generator, Tuple, Sequence

from sslyze import ServerTlsProbingResult
from sslyze.errors import ConnectionToServerFailed
from sslyze.scanner._mass_connectivity_tester import MassConnectivityTester
from sslyze.scanner._mass_scanner import (
    MassScannerProducerThread,
    NoMoreServerScanRequestsSentinel,
)
from sslyze.scanner.models import (
    ServerScanRequest,
    ServerScanResult,
    ServerConnectivityStatusEnum,
    ServerScanStatusEnum,
)


from sslyze.scanner.scanner_observer import ScannerObserver


class Scanner:
    def __init__(
        self,
        per_server_concurrent_connections_limit: Optional[int] = None,
        concurrent_server_scans_limit: Optional[int] = None,
        observers: Optional[Sequence[ScannerObserver]] = None,
    ):
        self._observers: Sequence[ScannerObserver]
        if observers is None:
            self._observers = []
        else:
            self._observers = observers

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

        self._connectivity_tester = MassConnectivityTester(self._concurrent_server_scans_count)

    def queue_scans(self, server_scan_requests: List[ServerScanRequest]) -> None:
        if self._has_started_work:
            raise ValueError("Already submitted scan requests")

        if not server_scan_requests:
            raise ValueError("Submitted emtpy list of server_scan_requests")

        # Start with connectivity testing
        self._connectivity_tester.start_work(server_scan_requests)

    @property
    def _has_started_work(self) -> bool:
        return self._connectivity_tester.has_started_work

    def get_results(self) -> Generator[ServerScanResult, None, None]:
        if not self._has_started_work:
            raise ValueError("No scan requests have been submitted")

        # Setup the queues for running and completing the scans
        server_scan_requests_queue: "queue.Queue[Tuple[ServerScanRequest, ServerTlsProbingResult]]" = queue.Queue()
        server_scan_results_queue: "queue.Queue[ServerScanResult]" = queue.Queue()

        def server_connectivity_test_completed_callback(
            server_scan_request: ServerScanRequest, connectivity_result: ServerTlsProbingResult
        ) -> None:
            for inner_observer in self._observers:
                inner_observer.server_connectivity_test_completed(server_scan_request, connectivity_result)

            # Since the server is reachable, queue the actual scan commands
            server_scan_requests_queue.put((server_scan_request, connectivity_result))

        def server_connectivity_test_error_callback(
            server_scan_request: ServerScanRequest, connectivity_error: ConnectionToServerFailed
        ) -> None:
            for inner_observer in self._observers:
                inner_observer.server_connectivity_test_error(server_scan_request, connectivity_error)

            # Since the server is not reachable, there is nothing else to do
            server_scan_results_queue.put(
                ServerScanResult(
                    uuid=server_scan_request.uuid,
                    server_location=server_scan_request.server_location,
                    network_configuration=server_scan_request.network_configuration,
                    connectivity_status=ServerConnectivityStatusEnum.ERROR,
                    connectivity_error_trace=TracebackException.from_exception(connectivity_error),
                    connectivity_result=None,
                    scan_status=ServerScanStatusEnum.ERROR_NO_CONNECTIVITY,
                    scan_result=None,
                )
            )

        # Initialize the MassScanner for running scan commands
        mass_scanner_thread = MassScannerProducerThread(
            concurrent_server_scans_count=self._concurrent_server_scans_count,
            per_server_concurrent_connections_count=self._per_server_concurrent_connections_count,
            server_scan_requests_queue_in=server_scan_requests_queue,
            server_scan_results_queue_out=server_scan_results_queue,
        )
        mass_scanner_thread.start()

        # Wait until all connectivity testing has been completed
        self._connectivity_tester.wait_until_all_work_was_processed(
            server_connectivity_test_completed_callback=server_connectivity_test_completed_callback,
            server_connectivity_test_error_callback=server_connectivity_test_error_callback,
        )

        # Notify the MassScanner that all the scan requests have been queued
        server_scan_requests_queue.put(NoMoreServerScanRequestsSentinel())  # type: ignore

        # Wait for all scans to finish
        while True:
            server_scan_result = server_scan_results_queue.get(block=True)
            server_scan_results_queue.task_done()
            if isinstance(server_scan_result, NoMoreServerScanRequestsSentinel):
                # All scans have been completed
                break

            # Notify observers and yield the completed scan
            for observer in self._observers:
                observer.server_scan_completed(server_scan_result)

            yield server_scan_result

        # All done with the scans
        server_scan_requests_queue.join()
        server_scan_results_queue.join()
        mass_scanner_thread.join()

        for observer in self._observers:
            observer.all_server_scans_completed()
