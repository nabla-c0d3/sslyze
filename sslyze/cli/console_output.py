from dataclasses import fields
from datetime import datetime
from pathlib import Path
from typing import TextIO, Optional

from sslyze import __version__, ServerScanRequest, ScanCommandAttemptStatusEnum, ScanCommandErrorReasonEnum
from sslyze.cli.command_line_parser import ParsedCommandLine

from sslyze.errors import ConnectionToServerFailed
from sslyze.plugins.plugin_base import ScanCommandWrongUsageError
from sslyze.plugins.scan_commands import ScanCommandsRepository, ScanCommand
from sslyze import ServerScanResult
from sslyze.scanner.models import ServerScanStatusEnum
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
from sslyze.scanner.scanner_observer import ScannerObserver
from sslyze.server_connectivity import ClientAuthRequirementEnum, ServerTlsProbingResult
from sslyze.server_setting import (
    ServerNetworkLocation,
    ConnectionTypeEnum,
)


class ObserverToGenerateConsoleOutput(ScannerObserver):
    def __init__(self, file_to: TextIO, json_path_out: Optional[Path] = None) -> None:
        self._file_to = file_to
        self._date_scans_started = datetime.utcnow()

        # Used to print the path where the JSON output was written
        self._json_path_out = json_path_out

    @classmethod
    def _format_title(cls, title: str) -> str:
        return f" {title.upper()}\n {'-' * len(title)}\n"

    def command_line_parsed(self, parsed_command_line: ParsedCommandLine) -> None:
        self._file_to.write("\n")
        self._file_to.write(self._format_title("Checking connectivity to server(s)"))
        self._file_to.write("\n")

        for bad_server_str in parsed_command_line.invalid_servers:
            self._file_to.write(
                f"   {bad_server_str.server_string:<35} => ERROR: {bad_server_str.error_message};"
                f" discarding scan.\n"
            )

    def server_connectivity_test_error(
        self, server_scan_request: ServerScanRequest, connectivity_error: ConnectionToServerFailed
    ) -> None:
        self._file_to.write(
            f"   {connectivity_error.server_location.display_string:<25}"
            f" => ERROR: {connectivity_error.error_message}; discarding scan.\n"
        )

    def server_connectivity_test_completed(
        self, server_scan_request: ServerScanRequest, connectivity_result: ServerTlsProbingResult
    ) -> None:
        client_auth_msg = ""
        client_auth_requirement = connectivity_result.client_auth_requirement
        if client_auth_requirement == ClientAuthRequirementEnum.REQUIRED:
            client_auth_msg = "  WARNING: Server REQUIRED client authentication, specific plugins will fail."
        elif client_auth_requirement == ClientAuthRequirementEnum.OPTIONAL:
            client_auth_msg = "  WARNING: Server requested optional client authentication"

        server_location = server_scan_request.server_location
        network_route = _server_location_to_network_route(server_location)
        self._file_to.write(f"   {server_location.display_string:<25} => {network_route} {client_auth_msg}\n")

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
            # Nothing to print here if the scan was not completed
            return

        # Generate the console output for each scan command
        scan_command_results_str = ""
        for result_field in fields(server_scan_result.scan_result):
            scan_command = ScanCommand(result_field.name)
            scan_command_attempt = getattr(server_scan_result.scan_result, scan_command)

            if scan_command_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                scan_command_results_str += "\n"
                cli_connector_cls = ScanCommandsRepository.get_implementation_cls(scan_command).cli_connector_cls
                for line in cli_connector_cls.result_to_console_output(scan_command_attempt.result):
                    scan_command_results_str += line + "\n"

            elif scan_command_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                scan_command_results_str += scan_command_error_as_console_output(
                    server_scan_result.server_location, scan_command, scan_command_attempt
                )

            elif scan_command_attempt.status == ScanCommandAttemptStatusEnum.NOT_SCHEDULED:
                pass

            else:
                raise ValueError("Should never happen")

        # Also display the server that was scanned
        server_location = server_scan_result.server_location
        network_route = _server_location_to_network_route(server_location)
        scan_txt = f"Scan Results For {server_location.display_string} - {network_route}"
        self._file_to.write("\n\n" + self._format_title(scan_txt) + scan_command_results_str)

    def all_server_scans_completed(self) -> None:
        scans_duration = datetime.utcnow() - self._date_scans_started
        self._file_to.write("\n")
        self._file_to.write(
            self._format_title(f"Scans Completed in {scans_duration.seconds}.{scans_duration.microseconds} s")
        )
        if self._json_path_out:
            self._file_to.write(f'\n       Wrote JSON output to "{self._json_path_out}".\n')


def _server_location_to_network_route(server_location: ServerNetworkLocation) -> str:
    if server_location.connection_type == ConnectionTypeEnum.VIA_HTTP_PROXY:
        # We do not know the server's IP address if going through a proxy
        assert server_location.http_proxy_settings
        network_route = "HTTP proxy at {}:{}".format(
            server_location.http_proxy_settings.hostname, server_location.http_proxy_settings.port
        )
    elif server_location.connection_type == ConnectionTypeEnum.DIRECT:
        assert server_location.ip_address
        network_route = server_location.ip_address
    else:
        raise ValueError("Should never happen")
    return network_route


def scan_command_error_as_console_output(
    server_location: ServerNetworkLocation, scan_command: ScanCommand, scan_command_attempt: ScanCommandAttempt
) -> str:
    if not scan_command_attempt.error_trace:
        raise ValueError("Should never happen")

    target_result_str = "\n"
    cli_connector_cls = ScanCommandsRepository.get_implementation_cls(scan_command).cli_connector_cls

    if scan_command_attempt.error_reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED:
        target_result_str += cli_connector_cls._format_title(
            f"Client certificated required for --{cli_connector_cls._cli_option}"
        )
        target_result_str += " use --cert and --key to provide one.\n"

    elif scan_command_attempt.error_reason == ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE:
        target_result_str += cli_connector_cls._format_title(
            f"Connection timed out or was rejected for --{cli_connector_cls._cli_option}"
        )
        target_result_str += " try using --slow_connection to reduce the impact on the server.\n"

    elif scan_command_attempt.error_reason == ScanCommandErrorReasonEnum.WRONG_USAGE:
        target_result_str += cli_connector_cls._format_title(f"Wrong usage for --{cli_connector_cls._cli_option}")
        # Extract the last line which contains the reason
        last_line = None
        for line in scan_command_attempt.error_trace.format(chain=False):
            last_line = line
        if last_line:
            exception_cls_in_trace = f"{ScanCommandWrongUsageError.__name__}:"
            if exception_cls_in_trace in last_line:
                details_text = last_line.split(exception_cls_in_trace)[1].strip()
                target_result_str += f"       {details_text}"
            else:
                target_result_str += f"       {last_line}"

    elif scan_command_attempt.error_reason == ScanCommandErrorReasonEnum.BUG_IN_SSLYZE:
        target_result_str += cli_connector_cls._format_title(f"Error when running --{cli_connector_cls._cli_option}")
        target_result_str += "\n"
        target_result_str += (
            "       You can open an issue at https://github.com/nabla-c0d3/sslyze/issues"
            " with the following information:\n\n"
        )
        target_result_str += f"       * SSLyze version: {__version__.__version__}\n"
        target_result_str += f"       * Server: {server_location.display_string}"
        target_result_str += f" - {_server_location_to_network_route(server_location)}\n"
        target_result_str += f"       * Scan command: {scan_command}\n\n"
        for line in scan_command_attempt.error_trace.format(chain=False):
            target_result_str += f"       {line}"
    else:
        raise ValueError("Should never happen")

    return target_result_str
