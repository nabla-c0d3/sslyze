import json
from io import StringIO

from sslyze.cli.json_output import JsonOutputGenerator
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner import ScanCommandError, ScanCommandErrorReasonEnum
from tests.factories import (
    ParsedCommandLineFactory,
    ConnectionToServerFailedFactory,
    ServerScanResultFactory,
    TracebackExceptionFactory,
)


class TestJsonOutputGenerator:
    def test_command_line_parsed(self):
        # Given a command line used to run sslyze
        parsed_cmd_line = ParsedCommandLineFactory.create()

        # Which contained some valid, and some invalid servers
        assert parsed_cmd_line.invalid_servers
        assert parsed_cmd_line.servers_to_scans

        # When generating the JSON output for this
        with StringIO() as file_out:
            json_generator = JsonOutputGenerator(file_out)
            json_generator.command_line_parsed(parsed_cmd_line)

            # We call scans_completed() because this is when the output actually gets written to the file
            json_generator.scans_completed(0.2)
            final_output = file_out.getvalue()

        # It succeeds and the invalid servers were displayed
        assert final_output
        for bad_server in parsed_cmd_line.invalid_servers:
            assert json.dumps(bad_server.server_string) in final_output
            assert json.dumps(bad_server.error_message) in final_output

    def test_server_connectivity_test_failed(self):
        # Given a server to scan to which sslyze could not connect
        error = ConnectionToServerFailedFactory.create()

        # When generating the JSON output for this
        with StringIO() as file_out:
            json_generator = JsonOutputGenerator(file_to=file_out)
            json_generator.server_connectivity_test_failed(error)

            # We call scans_completed() because this is when the output actually gets written to the file
            json_generator.scans_completed(0.2)
            final_output = file_out.getvalue()

        # It succeeds and the connectivity error was displayed
        assert final_output
        assert json.dumps(error.error_message) in final_output

    def test_server_scan_completed(self):
        # Given a completed scan for a server
        scan_results = {ScanCommand.TLS_COMPRESSION: CompressionScanResult(supports_compression=True)}
        scan_result = ServerScanResultFactory.create(scan_commands_results=scan_results)

        # When generating the JSON output for this server scan
        with StringIO() as file_out:
            json_generator = JsonOutputGenerator(file_to=file_out)
            json_generator.server_scan_completed(scan_result)

            # We call scans_completed() because this is when the output actually gets written to the file
            json_generator.scans_completed(0.2)
            final_output = file_out.getvalue()

        # It succeeds
        assert final_output
        assert "supports_compression" in final_output

    def test_server_scan_completed_with_error(self):
        # Given a completed scan for a server that triggered an error
        error_trace = TracebackExceptionFactory.create()
        scan_errors = {
            ScanCommand.TLS_COMPRESSION: ScanCommandError(
                reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE, exception_trace=error_trace
            )
        }
        scan_result = ServerScanResultFactory.create(scan_commands_errors=scan_errors)

        # When generating the JSON output for this server scan
        with StringIO() as file_out:
            json_generator = JsonOutputGenerator(file_to=file_out)
            json_generator.server_scan_completed(scan_result)

            # We call scans_completed() because this is when the output actually gets written to the file
            json_generator.scans_completed(0.2)
            final_output = file_out.getvalue()

        # It succeeds and displays the error
        assert final_output
        assert error_trace.exc_type.__name__ in final_output
