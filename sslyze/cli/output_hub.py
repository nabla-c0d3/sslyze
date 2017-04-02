# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import sys
from io import open
from sslyze.cli.console_output import ConsoleOutputGenerator
from sslyze.cli.json_output import JsonOutputGenerator
from sslyze.cli.xml_output import XmlOutputGenerator


class OutputHub(object):
    """Configure the SSLyze CLI's output and forward notification of events to all enabled output generators.
    """
    def __init__(self):
        self._output_generator_list = []

    def command_line_parsed(self, available_plugins, args_command_list):
        # Configure the console output
        should_print_text_results = not args_command_list.quiet and args_command_list.xml_file != '-' \
                                    and args_command_list.json_file != '-'
        if should_print_text_results:
            self._output_generator_list.append(ConsoleOutputGenerator(sys.stdout))

        # Configure the JSON output
        json_file_to = None
        if args_command_list.json_file:
            json_file_to = sys.stdout if args_command_list.json_file == '-' else open(args_command_list.json_file, 'wt')
        if json_file_to:
            self._output_generator_list.append(JsonOutputGenerator(json_file_to))

        # Configure the XML output
        xml_file_to = None
        if args_command_list.xml_file:
            xml_file_to = sys.stdout if args_command_list.xml_file == '-' else open(args_command_list.xml_file, 'wt')
        if xml_file_to:
            self._output_generator_list.append(XmlOutputGenerator(xml_file_to))

        # Forward the notification
        for out_generator in self._output_generator_list:
            out_generator.command_line_parsed(available_plugins, args_command_list)

    def server_connectivity_test_failed(self, failed_scan):
        for out_generator in self._output_generator_list:
            out_generator.server_connectivity_test_failed(failed_scan)

    def server_connectivity_test_succeeded(self, server_connectivity_info):
        for out_generator in self._output_generator_list:
            out_generator.server_connectivity_test_succeeded(server_connectivity_info)

    def scans_started(self):
        for out_generator in self._output_generator_list:
            out_generator.scans_started()

    def server_scan_completed(self, server_scan_result):
        for out_generator in self._output_generator_list:
            out_generator.server_scan_completed(server_scan_result)

    def scans_completed(self, total_scan_time):
        # Forward the notification and close all the file descriptors
        for out_generator in self._output_generator_list:
            out_generator.scans_completed(total_scan_time)
            out_generator.close()

