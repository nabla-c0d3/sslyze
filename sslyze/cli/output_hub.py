import sys
from io import open
from typing import Type, Any, Set, List

from sslyze.cli import CompletedServerScan
from sslyze.cli.command_line_parser import ServerStringParsingError
from sslyze.cli.console_output import ConsoleOutputGenerator
from sslyze.cli.json_output import JsonOutputGenerator
from sslyze.cli.output_generator import OutputGenerator
from sslyze.cli.xml_output import XmlOutputGenerator
from sslyze.plugins.plugin_base import Plugin
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.server_connectivity_tester import ServerConnectivityError


class OutputHub:
    """Configure the SSLyze CLI's output and forward notification of events to all enabled output generators.
    """
    def __init__(self) -> None:
        self._output_generator_list: List[OutputGenerator] = []

    def command_line_parsed(
            self,
            available_plugins: Set[Type[Plugin]],
            args_command_list: Any,
            malformed_servers: List[ServerStringParsingError]
    ) -> None:
        # Configure the console output
        should_print_text_results = not args_command_list.quiet and args_command_list.xml_file != '-' \
            and args_command_list.json_file != '-'
        if should_print_text_results:
            self._output_generator_list.append(ConsoleOutputGenerator(sys.stdout))

        # Configure the JSON output
        if args_command_list.json_file:
            json_file_to = sys.stdout if args_command_list.json_file == '-' else open(args_command_list.json_file, 'wt')
            self._output_generator_list.append(JsonOutputGenerator(json_file_to))  # type: ignore

        # Configure the XML output
        if args_command_list.xml_file:
            xml_file_to = sys.stdout if args_command_list.xml_file == '-' else open(args_command_list.xml_file, 'wt')
            self._output_generator_list.append(XmlOutputGenerator(xml_file_to))  # type: ignore

        # Forward the notification
        for out_generator in self._output_generator_list:
            out_generator.command_line_parsed(available_plugins, args_command_list, malformed_servers)

    def server_connectivity_test_failed(self, connectivity_error: ServerConnectivityError) -> None:
        for out_generator in self._output_generator_list:
            out_generator.server_connectivity_test_failed(connectivity_error)

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        for out_generator in self._output_generator_list:
            out_generator.server_connectivity_test_succeeded(server_connectivity_info)

    def scans_started(self) -> None:
        for out_generator in self._output_generator_list:
            out_generator.scans_started()

    def server_scan_completed(self, server_scan_result: CompletedServerScan) -> None:
        for out_generator in self._output_generator_list:
            out_generator.server_scan_completed(server_scan_result)

    def scans_completed(self, total_scan_time: float) -> None:
        # Forward the notification and close all the file descriptors
        for out_generator in self._output_generator_list:
            out_generator.scans_completed(total_scan_time)
            out_generator.close()
