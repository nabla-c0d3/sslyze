import secrets
from concurrent.futures import Future, as_completed, TimeoutError
from concurrent.futures.thread import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional

from sslyze.plugins.plugin_base import ServerScanRequest, ServerScanResult, ScanCommandResult
from sslyze.plugins.plugins_repository import PluginsRepository
from sslyze.plugins.scan_commands import ScanCommandEnum
from sslyze.server_connectivity_tester import ServerConnectivityInfo


class Scanner:

    def __init__(
        self,
        per_server_concurrent_connections_limit: Optional[int] = None,
        concurrent_server_scans_limit: Optional[int] = None
    ):
        self._plugins_repository = PluginsRepository()
        self._queued_future_to_server_and_scan_cmd: Dict[Future, (ServerConnectivityInfo, ScanCommandEnum)] = {}

        self._queued_server_scans: List[ServerScanRequest] = []
        self._pending_server_scan_results: Dict[ServerConnectivityInfo, Dict[ScanCommandEnum, ScanCommandResult]] = {}

        # Rate-limit how many connections the scanner will open
        # Total number of concurrent connections = final_server_scans_limit * final_per_server_connections_limit
        final_server_scans_limit = concurrent_server_scans_limit if concurrent_server_scans_limit else 10
        final_per_server_connections_limit = \
            per_server_concurrent_connections_limit if per_server_concurrent_connections_limit else 5

        self._all_thread_pools = [
            ThreadPoolExecutor(max_workers=final_per_server_connections_limit)
            for _ in range(final_server_scans_limit)
        ]
        self._server_to_thread_pool: Dict[ServerConnectivityInfo, ThreadPoolExecutor] = {}

    def queue_scan(self, server_scan: ServerScanRequest) -> None:
        # Only one scan per server can be submitted
        if server_scan.server_info in self._pending_server_scan_results:
            raise ValueError(f"Already submitted a scan for server {server_scan.server_info}")
        self._queued_server_scans.append(server_scan)
        self._pending_server_scan_results[server_scan.server_info] = {}

        # Assign the server to scan to a thread pool
        thread_pool_for_server = secrets.choice(self._all_thread_pools)
        self._server_to_thread_pool[server_scan.server_info] = thread_pool_for_server

        # Convert each scan command within the server scan request into jobs
        for scan_cmd_enum in server_scan.scan_commands:
            implementation_cls = scan_cmd_enum._get_implementation_cls()
            scan_cmd_extra_args = server_scan.scan_commands_extra_arguments.get(scan_cmd_enum)
            jobs_to_run = implementation_cls.scan_jobs_for_scan_command(
                server_info=server_scan.server_info,
                extra_arguments=scan_cmd_extra_args
            )

            # Schedule the jobs
            for job in jobs_to_run:
                future = thread_pool_for_server.submit(job.function_to_call, *job.function_arguments)
                self._queued_future_to_server_and_scan_cmd[future] = (server_scan.server_info, scan_cmd_enum)

    def get_results(self) -> Iterable[ServerScanResult]:
        server_and_scan_cmd_to_completed_futures: Dict[(ServerConnectivityInfo, ScanCommandEnum), List[Future]] = {
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
                    server_info, scan_cmd_enum = server_and_scan_cmd
                    implementation_cls = scan_cmd_enum._get_implementation_cls()
                    result = implementation_cls.result_for_completed_scan_jobs(
                        server_info,
                        server_and_scan_cmd_to_completed_futures[server_and_scan_cmd]
                    )
                    scan_cmds_completed.append(server_and_scan_cmd)
                    self._pending_server_scan_results[server_info][scan_cmd_enum] = result

            for server_and_scan_cmd in scan_cmds_completed:
                del server_and_scan_cmd_to_completed_futures[server_and_scan_cmd]

            # Lastly, have all the scan commands for a given server completed?
            for server_scan in self._queued_server_scans:
                if len(server_scan.scan_commands) == len(self._pending_server_scan_results[server_scan.server_info]):
                    # Yes - return the fully completed server scan
                    yield ServerScanResult(
                        scan_commands_results = self._pending_server_scan_results[server_scan.server_info],
                        server_info=server_scan.server_info,
                        scan_commands=server_scan.scan_commands,
                        scan_commands_extra_arguments=server_scan.scan_commands_extra_arguments,
                    )
                    del self._pending_server_scan_results[server_scan.server_info]


        self._shutdown_thread_pools()

    def _shutdown_thread_pools(self):
        [thread_pool.shutdown(wait=True) for thread_pool in self._all_thread_pools]

    def emergency_shutdown(self) -> None:
        for future in self._queued_future_to_server_and_scan_cmd:
            future.cancel()
        self._shutdown_thread_pools()
