import sys
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from sslyze.plugins.plugin_base import PluginScanResult

from sslyze.plugins.plugins_repository import PluginsRepository
from sslyze.cli.output_hub import OutputHub
from sslyze.cli import CompletedServerScan
from sslyze import __version__
from sslyze.cli.command_line_parser import CommandLineParsingError, CommandLineParser
import signal
from multiprocessing import freeze_support
from time import time

from sslyze.scanner import Scanner
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError, ServerConnectivityInfo
from sslyze.server_setting import ServerNetworkLocation

global_scanner: Optional[Scanner] = None


def sigint_handler(signum: int, frame: Any) -> None:
    print("Scan interrupted... shutting down.")
    if global_scanner:
        global_scanner.emergency_shutdown()
    sys.exit()


def main() -> None:
    global global_scanner

    # For py2exe builds
    freeze_support()

    # Handle SIGINT to terminate processes
    signal.signal(signal.SIGINT, sigint_handler)
    start_time = time()

    plugins_repository = PluginsRepository()
    available_plugins = plugins_repository.get_available_plugins()
    available_commands = plugins_repository.get_available_commands()

    # Create the command line parser and the list of available options
    sslyze_parser = CommandLineParser(available_plugins, __version__)
    try:
        good_servers, invalid_servers, args_command_list = sslyze_parser.parse_command_line()
    except CommandLineParsingError as e:
        print(e.get_error_msg())
        return

    output_hub = OutputHub()
    output_hub.command_line_parsed(available_plugins, args_command_list, invalid_servers)

    # Initialize the scanner that will concurrently run each scan command
    concurrent_server_scans_limit = None
    per_server_concurrent_connections_limit = None
    if args_command_list.https_tunnel:
        # All the connections will go through a single proxy; only scan one server at a time to not DOS the proxy
        concurrent_server_scans_limit = 1
    if args_command_list.slow_connection:
        # Go easy on the servers; only open 2 concurrent connections against each server
        per_server_concurrent_connections_limit = 2
    global_scanner = Scanner(per_server_concurrent_connections_limit, concurrent_server_scans_limit)

    # Figure out which hosts are up and fill the task queue with work to do
    connectivity_tester = ServerConnectivityTester()
    online_servers: List[ServerConnectivityInfo] = []
    with ThreadPoolExecutor(max_workers=10) as thread_pool:
        futures = [thread_pool.submit(connectivity_tester.perform, server_data) for server_data in good_servers]
        for completed_future in as_completed(futures):
            try:
                server_connectivity_info = completed_future.result()

                # Connectivity testing was successful - store the server's info
                online_servers.append(server_connectivity_info)
                output_hub.server_connectivity_test_succeeded(server_connectivity_info)

                # Send scan commands for this server to the scanner
                # TODO(AD): Fix this
                for scan_command in args_command_list:
                   global_scanner.queue_scan_command(scan_command)

            except ServerConnectivityError as e:
                # Process servers we were NOT able to connect to
                output_hub.server_connectivity_test_failed(e)

    # Keep track of how many scan command have to be performed for each target
    spawned_scan_commands_count = 0
    output_hub.scans_started()
    for scan_command_class in available_commands:
        if getattr(args_command_list, scan_command_class.get_cli_argument()):
            spawned_scan_commands_count += 1

    # Each host has a list of results
    result_dict: Dict[ServerNetworkLocation, List[PluginScanResult]] = {}
    for server_info in online_servers:
        result_dict[server_info.server_location] = []

    # Process the results as they come
    for plugin_result in global_scanner.get_results():
        server_info = plugin_result.server_info
        result_dict[server_info].append(plugin_result)

        if len(result_dict[server_info]) == spawned_scan_commands_count:
            # All scan commands for this server have been completed; send the result to the output hub
            output_hub.server_scan_completed(CompletedServerScan(server_info, result_dict[server_info]))

    # All done
    exec_time = time() - start_time
    output_hub.scans_completed(exec_time)


if __name__ == "__main__":
    main()
