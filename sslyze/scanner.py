import gc
from concurrent.futures import Future, wait
from concurrent.futures.thread import ThreadPoolExecutor
from dataclasses import dataclass, field, fields, replace as dataclasses_replace
from enum import unique, Enum, auto
from traceback import TracebackException
from typing import Any, cast, Dict, Iterable, Iterator, List, Set, Tuple, Optional

from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.elliptic_curves_plugin import SupportedEllipticCurvesScanResult

try:
    # Python 3.7
    from typing_extensions import TypedDict
except ModuleNotFoundError:
    # Python 3.8+
    from typing import TypedDict  # type: ignore

from sslyze.errors import ConnectionToServerTimedOut, TlsHandshakeTimedOut
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


@dataclass(frozen=True)
class ScanCommandResults:
    """A dictionary of results for every scan command that was scheduled against a specific server.
    """

    # Field is present if the corresponding scan command was scheduled and was run successfully
    certificate_info: Optional[CertificateInfoScanResult] = None
    ssl_2_0_cipher_suites: Optional[CipherSuitesScanResult] = None
    ssl_3_0_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_1_0_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_1_1_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_1_2_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_1_3_cipher_suites: Optional[CipherSuitesScanResult] = None
    tls_compression: Optional[CompressionScanResult] = None
    tls_1_3_early_data: Optional[EarlyDataScanResult] = None
    openssl_ccs_injection: Optional[OpenSslCcsInjectionScanResult] = None
    tls_fallback_scsv: Optional[FallbackScsvScanResult] = None
    heartbleed: Optional[HeartbleedScanResult] = None
    robot: Optional[RobotScanResult] = None
    session_renegotiation: Optional[SessionRenegotiationScanResult] = None
    session_resumption: Optional[SessionResumptionSupportScanResult] = None
    session_resumption_rate: Optional[SessionResumptionRateScanResult] = None
    http_headers: Optional[HttpHeadersScanResult] = None
    elliptic_curves: Optional[SupportedEllipticCurvesScanResult] = None

    def keys(self) -> Iterator[str]:
        for field_ in fields(self):
            key = field_.name
            if getattr(self, key) is not None:
                yield key

    def items(self) -> Iterator[Tuple[str, Any]]:
        for key in self.keys():
            yield key, getattr(self, key)

    def __len__(self) -> int:
        return len(list(self.keys()))


ScanCommandErrorsDict = Dict[ScanCommandType, ScanCommandError]


@dataclass(frozen=True)
class ServerScanResult:
    """The result of a ServerScanRequest that was completed by a Scanner.
    """

    scan_commands_results: ScanCommandResults
    scan_commands_errors: ScanCommandErrorsDict

    # What was passed in the corresponding ServerScanRequest
    server_info: ServerConnectivityInfo
    scan_commands: Set[ScanCommandType]
    scan_commands_extra_arguments: ScanCommandExtraArgumentsDict


@dataclass(frozen=True)
class _QueuedServerScan:
    server_scan_request: ServerScanRequest

    queued_scan_jobs_per_scan_command: Dict[ScanCommandType, Set[Future]]
    queued_on_thread_pool_at_index: int

    scan_command_errors_during_queuing: ScanCommandErrorsDict

    @property
    def all_queued_scan_jobs(self) -> Set[Future]:
        all_queued_scan_jobs = set()
        for scan_jobs in self.queued_scan_jobs_per_scan_command.values():
            all_queued_scan_jobs.update(scan_jobs)
        return all_queued_scan_jobs


class Scanner:
    """The main class to use in order to call and schedule SSLyze's scan commands from Python.
    """

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

        self._thread_pools: List[ThreadPoolExecutor] = []
        self._queued_server_scans: List[_QueuedServerScan] = []

    def _get_assigned_thread_pool_index(self) -> int:
        """Pick (and create if needed) a thread pool for an upcoming server scan.

        This is used to maximize speed by scanning different servers concurrently.
        """
        currently_queued_scans_count = len(self._queued_server_scans)
        allowed_thread_pools_count = self._concurrent_server_scans_count
        assigned_thread_pool_index = currently_queued_scans_count % allowed_thread_pools_count

        try:
            self._thread_pools[assigned_thread_pool_index]
        except IndexError:
            self._thread_pools.append(ThreadPoolExecutor(max_workers=self._per_server_concurrent_connections_count))

        return assigned_thread_pool_index

    def queue_scan(self, server_scan: ServerScanRequest) -> None:
        """Queue a server scan.
        """
        already_queued_server_info = {
            queued_scan.server_scan_request.server_info for queued_scan in self._queued_server_scans
        }
        # Only one scan per server can be submitted
        if server_scan.server_info in already_queued_server_info:
            raise ValueError(f"Already submitted a scan for server {server_scan.server_info.server_location}")

        # Assign the server to scan to a thread pool
        assigned_thread_pool_index = self._get_assigned_thread_pool_index()
        assigned_thread_pool = self._thread_pools[assigned_thread_pool_index]

        # Convert each scan command within the server scan request into jobs
        queued_futures_per_scan_command: Dict[ScanCommandType, Set[Future]] = {}
        scan_command_errors_during_queuing = {}
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
                scan_command_errors_during_queuing[scan_cmd] = error
            except Exception as e:
                error = ScanCommandError(
                    reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                    exception_trace=TracebackException.from_exception(e),
                )
                scan_command_errors_during_queuing[scan_cmd] = error

            # Schedule the jobs
            queued_futures_per_scan_command[scan_cmd] = set()
            for job in jobs_to_run:
                future = assigned_thread_pool.submit(job.function_to_call, *job.function_arguments)
                queued_futures_per_scan_command[scan_cmd].add(future)

        # Save everything as a queued scan
        self._queued_server_scans.append(
            _QueuedServerScan(
                server_scan_request=server_scan,
                queued_scan_jobs_per_scan_command=queued_futures_per_scan_command,
                queued_on_thread_pool_at_index=assigned_thread_pool_index,
                scan_command_errors_during_queuing=scan_command_errors_during_queuing,
            )
        )

    def get_results(self) -> Iterable[ServerScanResult]:
        """Return completed server scans.
        """
        ongoing_scan_jobs = set()
        for queued_server_scan in self._queued_server_scans:
            ongoing_scan_jobs.update(queued_server_scan.all_queued_scan_jobs)

        while ongoing_scan_jobs:
            # Every 0.3 seconds, check for completed jobs
            all_completed_scan_jobs, _ = wait(ongoing_scan_jobs, timeout=0.3)

            # Check if a server scan has been fully completed
            for queued_server_scan in self._queued_server_scans:
                if not queued_server_scan.all_queued_scan_jobs.issubset(all_completed_scan_jobs):
                    # This server scan still has jobs ongoing; check the next one
                    continue

                # If we get here, all the jobs for a specific server scan have been completed
                # Generate the result for each scan command
                server_scan_results = ScanCommandResults()
                server_scan_errors: ScanCommandErrorsDict = {}
                for scan_cmd, completed_scan_jobs in queued_server_scan.queued_scan_jobs_per_scan_command.items():
                    server_info = queued_server_scan.server_scan_request.server_info
                    implementation_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd)
                    try:
                        result = implementation_cls.result_for_completed_scan_jobs(
                            server_info, list(completed_scan_jobs)
                        )
                        scan_cmd_str = cast(str, scan_cmd)
                        server_scan_results = dataclasses_replace(server_scan_results, **{scan_cmd_str: result})

                    # Process exceptions that may have been raised while the jobs were being completed
                    except ClientCertificateRequested as e:
                        error = ScanCommandError(
                            reason=ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED,
                            exception_trace=TracebackException.from_exception(e),
                        )
                        server_scan_errors[scan_cmd] = error
                    except (ConnectionToServerTimedOut, TlsHandshakeTimedOut) as e:
                        error = ScanCommandError(
                            reason=ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE,
                            exception_trace=TracebackException.from_exception(e),
                        )
                        server_scan_errors[scan_cmd] = error
                    except Exception as e:
                        error = ScanCommandError(
                            reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                            exception_trace=TracebackException.from_exception(e),
                        )
                        server_scan_errors[scan_cmd] = error

                # Discard the corresponding jobs
                ongoing_scan_jobs.difference_update(queued_server_scan.all_queued_scan_jobs)

                # Lastly, return the fully completed server scan
                server_scan_errors.update(queued_server_scan.scan_command_errors_during_queuing)
                server_scan_result = ServerScanResult(
                    scan_commands_results=server_scan_results,
                    scan_commands_errors=server_scan_errors,
                    server_info=queued_server_scan.server_scan_request.server_info,
                    scan_commands=queued_server_scan.server_scan_request.scan_commands,
                    scan_commands_extra_arguments=queued_server_scan.server_scan_request.scan_commands_extra_arguments,
                )
                yield server_scan_result

        self._shutdown_thread_pools()

    def _shutdown_thread_pools(self) -> None:
        self._queued_server_scans = []
        for thread_pool in self._thread_pools:
            thread_pool.shutdown(wait=True)
        self._thread_pools = []

        # Force garbage collection because for some reason the Future objects created by ThreadPoolExecutor.submit()
        # take a ton of memory (compared to what they do - holding a function to call and its arguments):
        # https://stackoverflow.com/questions/45946274/rss-memory-usage-from-concurrent-futures
        # https://stackoverflow.com/questions/53104082/using-threadpoolexecutor-with-reduced-memory-footprint
        # https://stackoverflow.com/questions/34770169/using-concurrent-futures-without-running-out-of-ram
        # We force garbage collection here to ensure memory usage does not balloon when running SSLyze in some kind
        # of long-running app (such as a web app). Otherwise, the GC tends to not cleanup all the Future objects right
        # away (although at this point, all the work has been completed) and memory usage goes up like crazy
        gc.collect()

    def emergency_shutdown(self) -> None:
        for queued_server_scan in self._queued_server_scans:
            for future in queued_server_scan.all_queued_scan_jobs:
                future.cancel()
        self._shutdown_thread_pools()
