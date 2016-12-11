#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import os
import sys


if not hasattr(sys,"frozen"):
    sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))

from sslyze.cli.output_hub import OutputHub
from sslyze.cli import FailedServerScan, CompletedServerScan
from sslyze import __version__
from sslyze.cli.command_line_parser import CommandLineParsingError, CommandLineParser
import signal
from multiprocessing import freeze_support
from time import time
from sslyze.plugins_process_pool import PluginsProcessPool
from sslyze.plugins_finder import PluginsFinder
from sslyze.server_connectivity import ServersConnectivityTester


# Global so we can terminate processes when catching SIGINT
plugins_process_pool = None

def sigint_handler(signum, frame):
    print 'Scan interrupted... shutting down.'
    if plugins_process_pool:
        plugins_process_pool.emergency_shutdown()
    sys.exit()


def main():
    # For py2exe builds
    freeze_support()

    # Handle SIGINT to terminate processes
    signal.signal(signal.SIGINT, sigint_handler)

    start_time = time()

    # Retrieve available plugins
    sslyze_plugins = PluginsFinder()
    available_plugins = sslyze_plugins.get_plugins()
    available_commands = sslyze_plugins.get_commands()

    # Create the command line parser and the list of available options
    sslyze_parser = CommandLineParser(available_plugins, __version__)
    try:
        good_server_list, bad_server_list, args_command_list = sslyze_parser.parse_command_line()
    except CommandLineParsingError as e:
        print e.get_error_msg()
        return

    output_hub = OutputHub()
    output_hub.command_line_parsed(available_plugins, args_command_list)


    # Initialize the pool of processes that will run each plugin
    if args_command_list.https_tunnel:
        # Maximum one process to not kill the proxy
        plugins_process_pool = PluginsProcessPool(sslyze_plugins, args_command_list.nb_retries,
                                                  args_command_list.timeout, max_processes_nb=1)
    else:
        plugins_process_pool = PluginsProcessPool(sslyze_plugins, args_command_list.nb_retries,
                                                  args_command_list.timeout)


    # Figure out which hosts are up and fill the task queue with work to do
    connectivity_tester = ServersConnectivityTester(good_server_list)
    connectivity_tester.start_connectivity_testing(network_timeout=args_command_list.timeout)

    # Store and print server whose command line string was bad
    for failed_scan in bad_server_list:
        output_hub.server_connectivity_test_failed(failed_scan)

    # Store and print servers we were able to connect to
    online_servers_list = []
    for server_connectivity_info in connectivity_tester.get_reachable_servers():
        online_servers_list.append(server_connectivity_info)
        output_hub.server_connectivity_test_succeeded(server_connectivity_info)

        # Send tasks to worker processes
        for plugin_command in available_commands:
            if getattr(args_command_list, plugin_command):
                # Get this plugin's options if there's any
                plugin_options_dict = {}
                for option in available_commands[plugin_command].get_interface().get_options():
                    # Was this option set ?
                    if getattr(args_command_list,option.dest):
                        plugin_options_dict[option.dest] = getattr(args_command_list, option.dest)

                plugins_process_pool.queue_plugin_task(server_connectivity_info, plugin_command, plugin_options_dict)


    # Store and print servers we were NOT able to connect to
    for tentative_server_info, exception in connectivity_tester.get_invalid_servers():
        failed_scan = FailedServerScan(tentative_server_info.server_string, exception)
        output_hub.server_connectivity_test_failed(failed_scan)


    # Keep track of how many tasks have to be performed for each target
    task_num = 0
    output_hub.scans_started()
    for command in available_commands:
        if getattr(args_command_list, command):
            task_num += 1


    # Each host has a list of results
    result_dict = {}
    # We cannot use the server_info object directly as its address will change due to multiprocessing
    RESULT_KEY_FORMAT = u'{hostname}:{ip_address}:{port}'.format
    for server_info in online_servers_list:
        result_dict[RESULT_KEY_FORMAT(hostname=server_info.hostname, ip_address=server_info.ip_address,
                                      port=server_info.port)] = []

    # Process the results as they come
    for plugin_result in plugins_process_pool.get_results():
        server_info = plugin_result.server_info
        result_dict[RESULT_KEY_FORMAT(hostname=server_info.hostname, ip_address=server_info.ip_address,
                                      port=server_info.port)].append(plugin_result)

        plugin_result_list = result_dict[RESULT_KEY_FORMAT(hostname=server_info.hostname,
                                                           ip_address=server_info.ip_address,
                                                           port=server_info.port)]

        if len(plugin_result_list) == task_num:
            # Done with this server; send the result to the output hub
            output_hub.server_scan_completed(CompletedServerScan(server_info, plugin_result_list))


    # All done
    exec_time = time()-start_time
    output_hub.scans_completed(exec_time)


if __name__ == "__main__":
    main()
