from io import StringIO

from sslyze.cli.console_output import ObserverToGenerateConsoleOutput
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze import ScanCommandErrorReasonEnum, ScanCommandAttemptStatusEnum
from sslyze.scanner.models import CompressionScanAttempt
from sslyze.server_connectivity import ClientAuthRequirementEnum
from tests.factories import (
    ServerScanResultFactory,
    TracebackExceptionFactory,
    ServerNetworkLocationViaHttpProxyFactory,
    ParsedCommandLineFactory,
    ConnectionToServerFailedFactory,
    ServerScanRequestFactory,
    ServerTlsProbingResultFactory,
    AllScanCommandsAttemptsFactory,
)


class TestObserverToGenerateConsoleOutput:
    def test_command_line_parsed(self):
        # Given a command line used to run sslyze
        parsed_cmd_line = ParsedCommandLineFactory.create()

        # Which contained some valid, and some invalid servers
        assert parsed_cmd_line.invalid_servers
        assert parsed_cmd_line.servers_to_scans

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ObserverToGenerateConsoleOutput(file_to=file_out)
            console_gen.command_line_parsed(parsed_cmd_line)
            final_output = file_out.getvalue()

        # It succeeds and the invalid servers were displayed
        assert final_output
        for bad_server in parsed_cmd_line.invalid_servers:
            assert bad_server.server_string in final_output
            assert bad_server.error_message in final_output

    def test_server_connectivity_test_error(self):
        # Given a server to scan to which sslyze could not connect
        scan_request = ServerScanRequestFactory.create()
        error = ConnectionToServerFailedFactory.create()

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ObserverToGenerateConsoleOutput(file_to=file_out)
            console_gen.server_connectivity_test_error(scan_request, error)
            final_output = file_out.getvalue()

        # It succeeds and the connectivity error was displayed
        assert final_output
        assert error.error_message in final_output

    def test_server_connectivity_test_completed(self):
        # Given a server to scan to which sslyze was able to connect
        scan_request = ServerScanRequestFactory.create()
        connectivity_result = ServerTlsProbingResultFactory.create()

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ObserverToGenerateConsoleOutput(file_to=file_out)
            console_gen.server_connectivity_test_completed(scan_request, connectivity_result)
            final_output = file_out.getvalue()

        # It succeeds and the server is displayed
        assert final_output
        assert scan_request.server_location.hostname in final_output

    def test_server_connectivity_test_completed_with_required_client_auth(self):
        # Given a server to scan to which sslyze was able to connect
        scan_request = ServerScanRequestFactory.create()
        connectivity_result = ServerTlsProbingResultFactory.create(
            # And the server requires client authentication
            client_auth_requirement=ClientAuthRequirementEnum.REQUIRED,
        )

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ObserverToGenerateConsoleOutput(file_to=file_out)
            console_gen.server_connectivity_test_completed(scan_request, connectivity_result)
            final_output = file_out.getvalue()

        # It succeeds and the fact that the server requires client auth was displayed
        assert final_output
        assert "Server REQUIRED client authentication" in final_output

    def test_server_connectivity_test_completed_with_http_tunneling(self):
        # Given a server to scan to which sslyze was able to connect
        scan_request = ServerScanRequestFactory.create(
            # And sslyze connected to it via an HTTP proxy
            server_location=ServerNetworkLocationViaHttpProxyFactory.create()
        )
        connectivity_result = ServerTlsProbingResultFactory.create()

        # When generating the console output for this
        with StringIO() as file_out:
            console_gen = ObserverToGenerateConsoleOutput(file_to=file_out)
            console_gen.server_connectivity_test_completed(scan_request, connectivity_result)
            final_output = file_out.getvalue()

        # It succeeds and the fact that an HTTP proxy was used was displayed
        assert final_output
        assert "proxy" in final_output

    def test_server_scan_completed(self):
        # Given a completed scan for a server when the compression scan command was run
        compression_attempt = CompressionScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=CompressionScanResult(supports_compression=True),
        )
        scan_result = ServerScanResultFactory.create(
            scan_result=AllScanCommandsAttemptsFactory.create({"tls_compression": compression_attempt})
        )

        # When generating the console output for this server scan
        with StringIO() as file_out:
            console_gen = ObserverToGenerateConsoleOutput(file_to=file_out)
            console_gen.server_scan_completed(scan_result)
            final_output = file_out.getvalue()

        # It succeeds
        assert final_output
        assert "Compression" in final_output

    def test_server_scan_completed_with_proxy(self):
        # Given a completed scan for a server when the compression scan command was run
        compression_attempt = CompressionScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=CompressionScanResult(supports_compression=True),
        )
        scan_result = ServerScanResultFactory.create(
            # And sslyze connected to the server via an HTTP proxy
            server_location=ServerNetworkLocationViaHttpProxyFactory.create(),
            scan_result=AllScanCommandsAttemptsFactory.create({"tls_compression": compression_attempt}),
        )

        # When generating the console output for this server scan
        with StringIO() as file_out:
            console_gen = ObserverToGenerateConsoleOutput(file_to=file_out)
            console_gen.server_scan_completed(scan_result)
            final_output = file_out.getvalue()

        # It succeeds and mentions the HTTP proxy
        assert final_output
        assert "HTTP PROXY" in final_output
        assert "Compression" in final_output

    def test_server_scan_completed_with_error(self):
        # Given a completed scan for a server that triggered an error
        error_trace = TracebackExceptionFactory.create()
        compression_attempt = CompressionScanAttempt(
            status=ScanCommandAttemptStatusEnum.ERROR,
            error_reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
            error_trace=error_trace,
            result=None,
        )
        scan_result = ServerScanResultFactory.create(
            scan_result=AllScanCommandsAttemptsFactory.create({"tls_compression": compression_attempt})
        )

        # When generating the console output for this server scan
        with StringIO() as file_out:
            console_gen = ObserverToGenerateConsoleOutput(file_to=file_out)
            console_gen.server_scan_completed(scan_result)
            final_output = file_out.getvalue()

        # It succeeds and displays the error
        assert final_output
        assert error_trace.stack.format()[0] in final_output

    def test_scans_completed(self):
        # When generating the console output for when all scans got completed, it succeeds
        with StringIO() as file_out:
            console_gen = ObserverToGenerateConsoleOutput(file_to=file_out)
            console_gen.all_server_scans_completed()
