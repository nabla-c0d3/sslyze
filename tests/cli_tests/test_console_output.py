from io import StringIO

from sslyze.cli.console_output import ConsoleOutputGenerator
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner import ScanCommandError, ScanCommandErrorReasonEnum
from sslyze.server_connectivity import ServerTlsProbingResult, ClientAuthRequirementEnum, TlsVersionEnum
from tests.factories import (
    ServerScanResultFactory,
    TracebackExceptionFactory,
    ServerConnectivityInfoFactory,
    ServerNetworkLocationViaHttpProxyFactory,
    ParsedCommandLineFactory,
    ConnectionToServerFailedFactory,
)


class TestConsoleOutputGenerator:
    def test_command_line_parsed(self):
        # Given a command line used to run sslyze
        parsed_cmd_line = ParsedCommandLineFactory.create()

        # Which contained some valid, and some invalid servers
        assert parsed_cmd_line.invalid_servers
        assert parsed_cmd_line.servers_to_scans

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.command_line_parsed(parsed_cmd_line)
            final_output = file_out.getvalue()

        # It succeeds and the invalid servers were displayed
        assert final_output
        for bad_server in parsed_cmd_line.invalid_servers:
            assert bad_server.server_string in final_output
            assert bad_server.error_message in final_output

    def test_server_connectivity_test_failed(self):
        # Given a server to scan to which sslyze could not connect
        error = ConnectionToServerFailedFactory.create()

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.server_connectivity_test_failed(error)
            final_output = file_out.getvalue()

        # It succeeds and the connectivity error was displayed
        assert final_output
        assert error.error_message in final_output

    def test_server_connectivity_test_succeeded(self):
        # Given a server to scan to which sslyze was able to connect
        server_info = ServerConnectivityInfoFactory.create()

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.server_connectivity_test_succeeded(server_info)
            final_output = file_out.getvalue()

        # It succeeds and the server is displayed
        assert final_output
        assert server_info.server_location.hostname in final_output

    def test_server_connectivity_test_succeeded_with_required_client_auth(self):
        # Given a server to scan to which sslyze was able to connect
        server_info = ServerConnectivityInfoFactory.create(
            tls_probing_result=ServerTlsProbingResult(
                highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
                cipher_suite_supported="AES",
                # And the server requires client authentication
                client_auth_requirement=ClientAuthRequirementEnum.REQUIRED,
            )
        )

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.server_connectivity_test_succeeded(server_info)
            final_output = file_out.getvalue()

        # It succeeds and the fact that the server requires client auth was displayed
        assert final_output
        assert "Server REQUIRED client authentication" in final_output

    def test_server_connectivity_test_succeeded_with_http_tunneling(self):
        # Given a server to scan to which sslyze was able to connect
        server_info = ServerConnectivityInfoFactory.create(
            # And sslyze connected to it via an HTTP proxy
            server_location=ServerNetworkLocationViaHttpProxyFactory.create()
        )

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.server_connectivity_test_succeeded(server_info)
            final_output = file_out.getvalue()

        # It succeeds and the fact that an HTTP proxy was used was displayed
        assert final_output
        assert "proxy" in final_output

    def test_scans_started(self):
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.scans_started()
            final_output = file_out.getvalue()
        assert final_output

    def test_server_scan_completed(self):
        # Given a completed scan for a server
        scan_results = {ScanCommand.TLS_COMPRESSION: CompressionScanResult(supports_compression=True)}
        scan_result = ServerScanResultFactory.create(scan_commands_results=scan_results)

        # When generating the console output for this server scan
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.server_scan_completed(scan_result)
            final_output = file_out.getvalue()

        # It succeeds
        assert final_output
        assert "Compression" in final_output

    def test_server_scan_completed_with_proxy(self):
        # Given a completed scan for a server
        server_info = ServerConnectivityInfoFactory.create(
            # And sslyze connected to the server via an HTTP proxy
            server_location=ServerNetworkLocationViaHttpProxyFactory.create()
        )
        scan_results = {ScanCommand.TLS_COMPRESSION: CompressionScanResult(supports_compression=True)}
        scan_result = ServerScanResultFactory.create(server_info=server_info, scan_commands_results=scan_results)

        # When generating the console output for this server scan
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.server_scan_completed(scan_result)
            final_output = file_out.getvalue()

        # It succeeds and mentions the HTTP proxy
        assert final_output
        assert "HTTP PROXY" in final_output
        assert "Compression" in final_output

    def test_server_scan_completed_with_error(self):
        # Given a completed scan for a server that triggered an error
        error_trace = TracebackExceptionFactory.create()
        scan_errors = {
            ScanCommand.TLS_COMPRESSION: ScanCommandError(
                reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE, exception_trace=error_trace
            )
        }
        scan_result = ServerScanResultFactory.create(scan_commands_errors=scan_errors)

        # When generating the console output for this server scan
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.server_scan_completed(scan_result)
            final_output = file_out.getvalue()

        # It succeeds and displays the error
        assert final_output
        assert error_trace.stack.format()[0] in final_output

    def test_scans_completed(self):
        # Given the time sslyze took to complete all scans
        scan_time = 1.3

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ConsoleOutputGenerator(file_to=file_out)
            console_gen.scans_completed(scan_time)
            final_output = file_out.getvalue()

        # It succeeds and the total scan time is displayed
        assert str(scan_time) in final_output
