"""Main abstract plugin classes from which all the plugins should inherit.
"""

from abc import ABC, abstractmethod
from concurrent.futures import Future, ThreadPoolExecutor

from dataclasses import dataclass, field

from typing import List, Callable, Any, Set, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from sslyze.plugins.scan_commands import ScanCommandEnum  # noqa: F401
    from sslyze.server_connectivity import ServerConnectivityInfo


class ScanCommandResult(ABC):
    pass


class ScanCommandExtraArguments(ABC):
    pass


@dataclass(frozen=True)
class ServerScanRequest:
    server_info: "ServerConnectivityInfo"
    scan_commands: Set["ScanCommandEnum"]
    scan_commands_extra_arguments: Dict["ScanCommandEnum", ScanCommandExtraArguments] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """"Validate that the extra arguments match the scan commands.
        """
        if not self.scan_commands_extra_arguments:
            return

        for scan_command in self.scan_commands_extra_arguments:
            if scan_command not in self.scan_commands:
                raise ValueError(f"Received an extra argument for a scan command that wasn't enabled: {scan_command}")


@dataclass(frozen=True)
class ServerScanResult:
    scan_commands_results: Dict["ScanCommandEnum", ScanCommandResult]

    # What was passed in the corresponding ServerScanRequest
    server_info: "ServerConnectivityInfo"
    scan_commands: Set["ScanCommandEnum"]
    scan_commands_extra_arguments: Dict["ScanCommandEnum", ScanCommandExtraArguments]


@dataclass(frozen=True)
class ScanJob:
    """One scan job should encapsulate some kind of server testing that uses at most one network connection.

    This allows sslyze to accurately limit how many concurrent connections it opens to a single server.
    """

    function_to_call: Callable
    function_arguments: Any


class ScanCommandImplementation(ABC):
    @classmethod
    @abstractmethod
    def scan_jobs_for_scan_command(
        cls, server_info: "ServerConnectivityInfo", extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        pass

    @classmethod
    @abstractmethod
    def result_for_completed_scan_jobs(
        cls, server_info: "ServerConnectivityInfo", completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
        pass

    @classmethod
    def perform(
        cls, server_info: "ServerConnectivityInfo", extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> ScanCommandResult:
        """Utility method to run a scan command directly.

        This is useful for the test suite to run commands without using the Scanner class. It should NOT be used to
        actually run scans as this will be very slow (no multi-threading); use the Scanner class instead.
        """
        thread_pool = ThreadPoolExecutor(max_workers=1)

        all_jobs = cls.scan_jobs_for_scan_command(server_info, extra_arguments)
        all_futures = []
        for job in all_jobs:
            future = thread_pool.submit(job.function_to_call, *job.function_arguments)
            all_futures.append(future)

        result = cls.result_for_completed_scan_jobs(server_info, all_futures)
        return result
