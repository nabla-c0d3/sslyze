import sys
from typing import List

from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.cli.console_output import ConsoleOutputGenerator
from sslyze.cli.json_output import JsonOutputGenerator
from sslyze.cli.output_generator import OutputGenerator
from sslyze.errors import ConnectionToServerFailed
from sslyze.scanner import ServerScanResult
from sslyze.server_connectivity import ServerConnectivityInfo


class OutputHub:
    """Configure the SSLyze CLI's output and forward notification of events to all enabled output generators.
    """

    def __init__(self) -> None:
        self._output_generator_list: List[OutputGenerator] = []

    def command_line_parsed(self, parsed_command_line: ParsedCommandLine) -> None:
        if not parsed_command_line.should_disable_console_output:
            self._output_generator_list.append(ConsoleOutputGenerator(sys.stdout))

        if parsed_command_line.json_file_out:
            self._output_generator_list.append(JsonOutputGenerator(parsed_command_line.json_file_out))

        # Forward the notification
        for out_generator in self._output_generator_list:
            out_generator.command_line_parsed(parsed_command_line)

    def server_connectivity_test_failed(self, connectivity_error: ConnectionToServerFailed) -> None:
        for out_generator in self._output_generator_list:
            out_generator.server_connectivity_test_failed(connectivity_error)

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        for out_generator in self._output_generator_list:
            out_generator.server_connectivity_test_succeeded(server_connectivity_info)

    def scans_started(self) -> None:
        for out_generator in self._output_generator_list:
            out_generator.scans_started()

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        for out_generator in self._output_generator_list:
            out_generator.server_scan_completed(server_scan_result)

    def scans_completed(self, total_scan_time: float) -> None:
        # Forward the notification and close all the file descriptors
        for out_generator in self._output_generator_list:
            out_generator.scans_completed(total_scan_time)
            out_generator.close()
