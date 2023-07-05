fromToggle navigation
Toggle navigation
 Subnet Calculator
148.66.54.79
 
Input
148.66.54.79/29
CIDR
148.66.54.72/29
Input IP
148.66.54.79
CIDR IP Range
148.66.54.72 - 148.66.54.79
Input Long
2487367247
CIDR Long Range
2487367240 - 2487367247
Input Hex
94.42.36.4F
CIDR Hex Range
94.42.36.48 - 94.42.36.4F
IPs in Range
8
Mask Bits
29
Subnet Mask
255.255.255.248
Hex Subnet Mask
FF.FF.FF.F8
ABOUT SUBNET CALCULATOR
The subnet calculator lets you enter a subnet range (CIDR) and see IP address information about that range You can type your range directly in CIDR notation, or use the optional Mask pull-down:

74.125.227.0/29
74.125.227.0, then select Optional Mask from dropdown
This is a useful feature for service providers and network operator who frequently allocate and work with subnets. CIDR stands for Classless Inter-Domain Routing, and refers to the standard of dividing the entire IP address space into smaller networks of variable size.

Your IP is: 102.89.33.103|  Contact Terms & Conditions Site Map API Privacy Phone: (866)-MXTOOLBOX / (866)-698-6652 |  © Copyright 2004-2021, MXToolBox, Inc, All rights reserved. US Patents 10839353 B2 & 11461738 B2
 
burritos@banana-pancakes.com braunstrowman@banana-pancakes.com finnbalor@banana-pancakes.com ricflair@banana-pancakes.com randysavage@banana-pancakes.com io import StringIO

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
