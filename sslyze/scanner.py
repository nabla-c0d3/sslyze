import secrets
from concurrent.futures import Future, as_completed, TimeoutError
from concurrent.futures.thread import ThreadPoolExecutor
from typing import Dict, Iterable, List

from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10Implementation
from sslyze.plugins.plugin_base import ScanCommand, ScanCommandResult
from sslyze.plugins.plugins_repository import PluginsRepository
from sslyze.server_connectivity_info import ServerNetworkLocation


class Scanner:

    # Controls every socket connection done by every plugin
    DEFAULT_NETWORK_RETRIES = 3
    DEFAULT_NETWORK_TIMEOUT = 5  # in seconds

    def __init__(self, per_server_concurrent_connections_limit: int = 5, concurrent_server_scans_limit: int = 10):
        self._plugins_repository = PluginsRepository()

        # To rate-limit how connections per server
        # Total number of concurrent connections = concurrent_server_scans_limit * per_server_concurrent_connections_limit
        self._all_thread_pools = [
            ThreadPoolExecutor(max_workers=per_server_concurrent_connections_limit)
            for _ in range(concurrent_server_scans_limit)
        ]
        self._server_to_thread_pool: Dict[ServerNetworkLocation, ThreadPoolExecutor] = {}

        self._queued_future_to_scan_command: Dict[Future, ScanCommand] = {}

    def queue_scan_command(self, scan_cmd: ScanCommand) -> None:
        # Convert the scan command into jobs
        # TODO
        #plugin_cls = self._plugins_repository.get_plugin_class_for_command(scan_command)
        plugin_cls = Tlsv10Implementation
        plugin = plugin_cls()

        jobs = plugin.scan_jobs_for_scan_command(scan_cmd)

        server_network_location = scan_cmd.server_info.network_location
        if server_network_location not in self._server_to_thread_pool:
            # New server to scan - assign it a thread pool randomly
            self._server_to_thread_pool[server_network_location] = secrets.choice(self._all_thread_pools)

        thread_pool = self._server_to_thread_pool[server_network_location]
        for job in jobs:
            future = thread_pool.submit(job.function_to_call, *job.function_arguments)
            self._queued_future_to_scan_command[future] = scan_cmd

    def get_results(self) -> Iterable[ScanCommandResult]:
        scan_command_to_completed_futures: Dict[ScanCommand, List[Future]] = {
            scan_cmd: [] for scan_cmd in self._queued_future_to_scan_command.values()
        }

        jobs_completed_count = 0
        jobs_total_count = len(self._queued_future_to_scan_command)
        while jobs_completed_count < jobs_total_count:
            # Every 1 seconds, process all the results
            try:
                for completed_future in as_completed(self._queued_future_to_scan_command.keys(), timeout=1):
                    jobs_completed_count += 1
                    # Move the future from "queued" to "completed"
                    scan_cmd = self._queued_future_to_scan_command[completed_future]
                    del self._queued_future_to_scan_command[completed_future]
                    scan_command_to_completed_futures[scan_cmd].append(completed_future)
            except TimeoutError:
                pass

            # Have all the scans of a given scan command completed?
            scan_cmds_completed = []
            for scan_cmd in scan_command_to_completed_futures:
                if scan_cmd not in self._queued_future_to_scan_command.values():
                    # Yes - return a result
                    # TODO
                    plugin_cls = Tlsv10Implementation
                    plugin = plugin_cls()

                    result = plugin.result_for_completed_scan_jobs(
                        scan_cmd,
                        scan_command_to_completed_futures[scan_cmd]
                    )
                    scan_cmds_completed.append(scan_cmd)
                    yield result

            for scan_cmd in scan_cmds_completed:
                del scan_command_to_completed_futures[scan_cmd]


        self._shutdown_thread_pools()

    def emergency_shutdown(self) -> None:
        for future in self._queued_future_to_scan_command:
            future.cancel()
        self._shutdown_thread_pools()

    def _shutdown_thread_pools(self):
        [thread_pool.shutdown(wait=True) for thread_pool in self._all_thread_pools]
