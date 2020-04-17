from concurrent.futures import Future, as_completed, TimeoutError
from concurrent.futures.thread import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import unique, Enum, auto
from traceback import TracebackException
from typing import Dict, Iterable, List, Tuple, Set, Optional

from nassl.ssl_client import ClientCertificateRequested

try:
    # Python 3.7
    from typing_extensions import TypedDict
except ModuleNotFoundError:
    # Python 3.8+
    from typing import TypedDict  # type: ignore

from sslyze.errors import ConnectionToServerTimedOut
from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult, CertificateInfoExtraArguments
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.early_data_plugin import EarlyDataScanResult
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanResult
from sslyze.plugins.heartbleed_plugin import HeartbleedScanResult
from sslyze.plugins.http_headers_plugin import HttpHeadersScanResult
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanResult
from sslyze.plugins.openssl_cipher_suites.implementation import CipherSuitesScanResult
from sslyze.plugins.plugin_base import ScanCommandWrongUsageError
from sslyze.plugins.robot.implementation import RobotScanResult
from sslyze.plugins.scan_commands import ScanCommandType, ScanCommandsRepository
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanResult
from sslyze.plugins.session_resumption.implementation import (
    SessionResumptionSupportScanResult,
    SessionResumptionRateScanResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo


@unique
class ScanCommandErrorReasonEnum(Enum):
    BUG_IN_SSLYZE = auto()
    CLIENT_CERTIFICATE_NEEDED = auto()
    CONNECTIVITY_ISSUE = auto()
    WRONG_USAGE = auto()


@dataclass(frozen=True)
class ScanCommandError:
    """An error that prevented a specific scan command ran against a specific server from completing.
    ."""

    reason: ScanCommandErrorReasonEnum
    exception_trace: TracebackException


class ScanCommandExtraArgumentsDict(TypedDict, total=False):
    # Field is present if extra arguments were provided for the corresponding scan command
    # Right now only certificate_info supports extra arguments
    certificate_info: CertificateInfoExtraArguments


@dataclass(frozen=True)
class ServerScanRequest:
    """A request to scan a specific server with the supplied scan commands.
    """

    server_info: ServerConnectivityInfo
    scan_commands: Set[ScanCommandType]
    scan_commands_extra_arguments: ScanCommandExtraArgumentsDict = field(default_factory=dict)  # type: ignore

    def __post_init__(self) -> None:
        """"Validate that the extra arguments match the scan commands.
        """
        if not self.scan_commands_extra_arguments:
            return

        for scan_command in self.scan_commands_extra_arguments:
            if scan_command not in self.scan_commands:
                raise ValueError(f"Received an extra argument for a scan command that wasn't enabled: {scan_command}")


# TypedDict for simpler/matching JSON output and makes fetching a field easier
class ScanCommandResultsDict(TypedDict, total=False):
    """A dictionary of results for every scan command that was scheduled against a specific server.
    """

    # Field is present if the corresponding scan command was scheduled and was run successfully
    certificate_info: CertificateInfoScanResult
    ssl_2_0_cipher_suites: CipherSuitesScanResult
    ssl_3_0_cipher_suites: CipherSuitesScanResult
    tls_1_0_cipher_suites: CipherSuitesScanResult
    tls_1_1_cipher_suites: CipherSuitesScanResult
    tls_1_2_cipher_suites: CipherSuitesScanResult
    tls_1_3_cipher_suites: CipherSuitesScanResult
    tls_compression: CompressionScanResult
    tls_1_3_early_data: EarlyDataScanResult
    openssl_ccs_injection: OpenSslCcsInjectionScanResult
    tls_fallback_scsv: FallbackScsvScanResult
    heartbleed: HeartbleedScanResult
    robot: RobotScanResult
    session_renegotiation: SessionRenegotiationScanResult
    session_resumption: SessionResumptionSupportScanResult
    session_resumption_rate: SessionResumptionRateScanResult
    http_headers: HttpHeadersScanResult


ScanCommandErrorsDict = Dict[ScanCommandType, ScanCommandError]


@dataclass(frozen=True)
class ServerScanResult:
    """The result of a ServerScanRequest that was completed by a Scanner.
    """

    scan_commands_results: ScanCommandResultsDict
    scan_commands_errors: ScanCommandErrorsDict

    # What was passed in the corresponding ServerScanRequest
    server_info: ServerConnectivityInfo
    scan_commands: Set[ScanCommandType]
    scan_commands_extra_arguments: ScanCommandExtraArgumentsDict


class Scanner:
    """The main class to use in order to call and schedule SSLyze's scan commands from Python.
    """

    def __init__(
        self,
        per_server_concurrent_connections_limit: Optional[int] = None,
        concurrent_server_scans_limit: Optional[int] = None,
    ):
        self._queued_server_scans: List[ServerScanRequest] = []
        self._queued_future_to_server_and_scan_cmd: Dict[Future, Tuple[ServerConnectivityInfo, ScanCommandType]] = {}
        self._pending_server_scan_results: Dict[ServerConnectivityInfo, ScanCommandResultsDict] = {}
        self._pending_server_scan_errors: Dict[ServerConnectivityInfo, ScanCommandErrorsDict] = {}

        # Setup default values
        if per_server_concurrent_connections_limit is None:
            final_per_server_concurrent_connections_limit = 5
        else:
            final_per_server_concurrent_connections_limit = per_server_concurrent_connections_limit
        if concurrent_server_scans_limit is None:
            final_concurrent_server_scans_limit = 10
        else:
            final_concurrent_server_scans_limit = concurrent_server_scans_limit

        # Rate-limit how many connections the scanner will open
        # Total number of concurrent connections = server_scans_limit * per_server_connections_limit
        self._all_thread_pools = [
            ThreadPoolExecutor(max_workers=final_per_server_concurrent_connections_limit)
            for _ in range(final_concurrent_server_scans_limit)
        ]
        self._server_to_thread_pool: Dict[ServerConnectivityInfo, ThreadPoolExecutor] = {}

    def queue_scan(self, server_scan: ServerScanRequest) -> None:
        """Queue a server scan.
        """
        # Only one scan per server can be submitted
        if server_scan.server_info in self._pending_server_scan_results:
            raise ValueError(f"Already submitted a scan for server {server_scan.server_info.server_location}")
        self._queued_server_scans.append(server_scan)
        self._pending_server_scan_results[server_scan.server_info] = {}
        self._pending_server_scan_errors[server_scan.server_info] = {}

        # Assign the server to scan to a thread pool
        server_scans_count = len(self._queued_server_scans)
        thread_pools_count = len(self._all_thread_pools)
        thread_pool_index_to_pick = server_scans_count % thread_pools_count
        thread_pool_for_server = self._all_thread_pools[thread_pool_index_to_pick]
        self._server_to_thread_pool[server_scan.server_info] = thread_pool_for_server

        # Convert each scan command within the server scan request into jobs
        for scan_cmd in server_scan.scan_commands:
            implementation_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd)
            scan_cmd_extra_args = server_scan.scan_commands_extra_arguments.get(scan_cmd)  # type: ignore

            jobs_to_run = []
            try:
                jobs_to_run = implementation_cls.scan_jobs_for_scan_command(
                    server_info=server_scan.server_info, extra_arguments=scan_cmd_extra_args
                )
            # Process exceptions and instantly "complete" the scan command if the call to create the jobs failed
            except ScanCommandWrongUsageError as e:
                error = ScanCommandError(
                    reason=ScanCommandErrorReasonEnum.WRONG_USAGE, exception_trace=TracebackException.from_exception(e)
                )
                self._pending_server_scan_errors[server_scan.server_info][scan_cmd] = error
            except Exception as e:
                error = ScanCommandError(
                    reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                    exception_trace=TracebackException.from_exception(e),
                )
                self._pending_server_scan_errors[server_scan.server_info][scan_cmd] = error

            # Schedule the jobs
            for job in jobs_to_run:
                future = thread_pool_for_server.submit(job.function_to_call, *job.function_arguments)
                self._queued_future_to_server_and_scan_cmd[future] = (server_scan.server_info, scan_cmd)

    def get_results(self) -> Iterable[ServerScanResult]:
        """Return completed server scans.
        """
        server_and_scan_cmd_to_completed_futures: Dict[Tuple[ServerConnectivityInfo, ScanCommandType], List[Future]] = {
            server_and_scan_cmd: [] for server_and_scan_cmd in self._queued_future_to_server_and_scan_cmd.values()
        }

        jobs_completed_count = 0
        jobs_total_count = len(self._queued_future_to_server_and_scan_cmd)
        while jobs_completed_count < jobs_total_count:
            # Every 1 seconds, process all the results
            try:
                for completed_future in as_completed(self._queued_future_to_server_and_scan_cmd.keys(), timeout=1):
                    jobs_completed_count += 1
                    # Move the future from "queued" to "completed"
                    server_and_scan_cmd = self._queued_future_to_server_and_scan_cmd[completed_future]
                    del self._queued_future_to_server_and_scan_cmd[completed_future]
                    server_and_scan_cmd_to_completed_futures[server_and_scan_cmd].append(completed_future)
            except TimeoutError:
                pass

            # Have all the jobs of a given scan command completed?
            scan_cmds_completed = []
            for server_and_scan_cmd in server_and_scan_cmd_to_completed_futures:
                if server_and_scan_cmd not in self._queued_future_to_server_and_scan_cmd.values():
                    # Yes - store the result
                    server_info, scan_cmd = server_and_scan_cmd
                    implementation_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd)

                    try:
                        result = implementation_cls.result_for_completed_scan_jobs(
                            server_info, server_and_scan_cmd_to_completed_futures[server_and_scan_cmd]
                        )
                        self._pending_server_scan_results[server_info][scan_cmd] = result

                    # Process exceptions that may have been raised while the jobs were being completed
                    except ClientCertificateRequested as e:
                        error = ScanCommandError(
                            reason=ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED,
                            exception_trace=TracebackException.from_exception(e),
                        )
                        self._pending_server_scan_errors[server_info][scan_cmd] = error
                    except ConnectionToServerTimedOut as e:
                        error = ScanCommandError(
                            reason=ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE,
                            exception_trace=TracebackException.from_exception(e),
                        )
                        self._pending_server_scan_errors[server_info][scan_cmd] = error
                    except Exception as e:
                        error = ScanCommandError(
                            reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                            exception_trace=TracebackException.from_exception(e),
                        )
                        self._pending_server_scan_errors[server_info][scan_cmd] = error

                    finally:
                        scan_cmds_completed.append(server_and_scan_cmd)

            for server_and_scan_cmd in scan_cmds_completed:
                del server_and_scan_cmd_to_completed_futures[server_and_scan_cmd]

            # Lastly, have all the scan commands for a given server completed?
            completed_server_scan_indexes: List[int] = []
            for index, server_scan in enumerate(self._queued_server_scans):
                scan_commands_processed_count = len(self._pending_server_scan_results[server_scan.server_info]) + len(
                    self._pending_server_scan_errors[server_scan.server_info]
                )
                if len(server_scan.scan_commands) == scan_commands_processed_count:
                    # Yes - return the fully completed server scan
                    yield ServerScanResult(
                        scan_commands_results=self._pending_server_scan_results[server_scan.server_info],
                        scan_commands_errors=self._pending_server_scan_errors[server_scan.server_info],
                        server_info=server_scan.server_info,
                        scan_commands=server_scan.scan_commands,
                        scan_commands_extra_arguments=server_scan.scan_commands_extra_arguments,
                    )
                    del self._pending_server_scan_results[server_scan.server_info]
                    del self._pending_server_scan_errors[server_scan.server_info]
                    completed_server_scan_indexes.append(index)

            # Remove the completed server scans - highest to lowest indexes as otherwise indexes to delete would no
            # longer be valid while the loop is running
            for index in reversed(completed_server_scan_indexes):
                del self._queued_server_scans[index]

        self._shutdown_thread_pools()

    def _shutdown_thread_pools(self) -> None:
        for thread_pool in self._all_thread_pools:
            thread_pool.shutdown(wait=True)

    def emergency_shutdown(self) -> None:
        for future in self._queued_future_to_server_and_scan_cmd:
            future.cancel()
        self._shutdown_thread_pools()
