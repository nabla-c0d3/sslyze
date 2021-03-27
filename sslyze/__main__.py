from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor

from sslyze.cli.output_hub import OutputHub
from sslyze.__version__ import __version__
from sslyze.cli.command_line_parser import CommandLineParsingError, CommandLineParser
from time import time

from sslyze.errors import ConnectionToServerFailed
from sslyze.scanner import Scanner, ServerScanRequest
from sslyze.server_connectivity import ServerConnectivityTester


def main() -> None:
    start_time = time()

    # Create the command line parser and the list of available options
    sslyze_parser = CommandLineParser(__version__)
    try:
        # Parse the supplied command line
        parsed_command_line = sslyze_parser.parse_command_line()
    except CommandLineParsingError as e:
        print(e.get_error_msg())
        return

    output_hub = OutputHub()
    output_hub.command_line_parsed(parsed_command_line)

    # Figure out which servers are reachable
    connectivity_tester = ServerConnectivityTester()
    all_server_scan_requests = []
    with ThreadPoolExecutor(max_workers=10) as thread_pool:
        futures = [
            thread_pool.submit(connectivity_tester.perform, server_location, network_config)
            for server_location, network_config in parsed_command_line.servers_to_scans
        ]
        for completed_future in as_completed(futures):
            try:
                server_connectivity_info = completed_future.result()
                output_hub.server_connectivity_test_succeeded(server_connectivity_info)

                # Server is only; add it to the list of servers to scan
                scan_request = ServerScanRequest(
                    server_info=server_connectivity_info,
                    scan_commands=parsed_command_line.scan_commands,
                    scan_commands_extra_arguments=parsed_command_line.scan_commands_extra_arguments,
                )
                all_server_scan_requests.append(scan_request)

            except ConnectionToServerFailed as e:
                output_hub.server_connectivity_test_failed(e)

    # For the servers that are reachable, start the scans
    output_hub.scans_started()
    if all_server_scan_requests:
        sslyze_scanner = Scanner(
            per_server_concurrent_connections_limit=parsed_command_line.per_server_concurrent_connections_limit,
            concurrent_server_scans_limit=parsed_command_line.concurrent_server_scans_limit,
        )
        sslyze_scanner.start_scans(all_server_scan_requests)

        # Process the results as they come
        for scan_result in sslyze_scanner.get_results():
            output_hub.server_scan_completed(scan_result)

    # All done
    exec_time = time() - start_time
    output_hub.scans_completed(exec_time)


if __name__ == "__main__":
    main()
