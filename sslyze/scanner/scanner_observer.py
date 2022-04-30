from abc import ABC, abstractmethod

from sslyze import ServerScanRequest, ServerTlsProbingResult, ServerScanResult
from sslyze.errors import ConnectionToServerFailed


# Could be turned into a typing.Protocol once we stop supporting Python 3.7
class ScannerObserver(ABC):
    @abstractmethod
    def server_connectivity_test_error(
        self, server_scan_request: ServerScanRequest, connectivity_error: ConnectionToServerFailed
    ) -> None:
        """The Scanner found a server that it could not connect to; no scans will be performed against this server."""

    @abstractmethod
    def server_connectivity_test_completed(
        self, server_scan_request: ServerScanRequest, connectivity_result: ServerTlsProbingResult
    ) -> None:
        """The Scanner found a server that it was able to connect to; scans will be run against this server."""

    @abstractmethod
    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        """The Scanner finished scanning one single server."""

    @abstractmethod
    def all_server_scans_completed(self) -> None:
        """The Scanner finished scanning all the supplied servers and will now exit."""
