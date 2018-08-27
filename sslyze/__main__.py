import sys
from typing import Any, Text, Dict, List

from sslyze.plugins.plugin_base import PluginScanResult

from sslyze.concurrent_scanner import ConcurrentScanner
from sslyze.plugins.plugins_repository import PluginsRepository
from sslyze.cli.output_hub import OutputHub
from sslyze.cli import CompletedServerScan
from sslyze import __version__
from sslyze.cli.command_line_parser import CommandLineParsingError, CommandLineParser
import signal
from multiprocessing import freeze_support
from time import time
from sslyze.server_connectivity_tester import ConcurrentServerConnectivityTester

global_scanner = None


def sigint_handler(signum: int, frame: Any) -> None:
    print('Scan interrupted... shutting down.')
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
        good_server_list, malformed_server_list, args_command_list = sslyze_parser.parse_command_line()
    except CommandLineParsingError as e:
        print(e.get_error_msg())
        return

    output_hub = OutputHub()
    output_hub.command_line_parsed(available_plugins, args_command_list, malformed_server_list)

    # Initialize the pool of processes that will run each plugin
    if args_command_list.https_tunnel or args_command_list.slow_connection:
        # Maximum one process to not kill the proxy or the connection
        global_scanner = ConcurrentScanner(max_processes_nb=1)
    else:
        global_scanner = ConcurrentScanner()

    # Figure out which hosts are up and fill the task queue with work to do
    connectivity_tester = ConcurrentServerConnectivityTester(good_server_list)
    connectivity_tester.start_connectivity_testing()

    # Store and print servers we were able to connect to
    online_servers_list = []
    for server_connectivity_info in connectivity_tester.get_reachable_servers():
        online_servers_list.append(server_connectivity_info)
        output_hub.server_connectivity_test_succeeded(server_connectivity_info)

        # Send tasks to worker processes
        for scan_command_class in available_commands:
            if getattr(args_command_list, scan_command_class.get_cli_argument()):
                # Get this command's optional argument if there's any
                optional_args = {}
                for optional_arg_name in scan_command_class.get_optional_arguments():
                    # Was this option set ?
                    if getattr(args_command_list, optional_arg_name):
                        optional_args[optional_arg_name] = getattr(args_command_list, optional_arg_name)
                scan_command = scan_command_class(**optional_args)  # type: ignore

                global_scanner.queue_scan_command(server_connectivity_info, scan_command)

    # Store and print servers we were NOT able to connect to
    for connectivity_exception in connectivity_tester.get_invalid_servers():
        output_hub.server_connectivity_test_failed(connectivity_exception)

    # Keep track of how many tasks have to be performed for each target
    task_num = 0
    output_hub.scans_started()
    for scan_command_class in available_commands:
        if getattr(args_command_list, scan_command_class.get_cli_argument()):
            task_num += 1

    # Each host has a list of results
    result_dict: Dict[Text, List[PluginScanResult]] = {}
    # We cannot use the server_info object directly as its address will change due to multiprocessing
    RESULT_KEY_FORMAT = '{hostname}:{ip_address}:{port}'
    for server_info in online_servers_list:
        result_dict[RESULT_KEY_FORMAT.format(hostname=server_info.hostname, ip_address=server_info.ip_address,
                                             port=server_info.port)] = []

    # Process the results as they come
    for plugin_result in global_scanner.get_results():
        server_info = plugin_result.server_info
        result_dict[RESULT_KEY_FORMAT.format(hostname=server_info.hostname, ip_address=server_info.ip_address,
                                             port=server_info.port)].append(plugin_result)

        plugin_result_list = result_dict[RESULT_KEY_FORMAT.format(hostname=server_info.hostname,
                                                                  ip_address=server_info.ip_address,
                                                                  port=server_info.port)]

        if len(plugin_result_list) == task_num:
            # Done with this server; send the result to the output hub
            output_hub.server_scan_completed(CompletedServerScan(server_info, plugin_result_list))

    # All done
    exec_time = time() - start_time
    output_hub.scans_completed(exec_time)


if __name__ == '__main__':
    main()
