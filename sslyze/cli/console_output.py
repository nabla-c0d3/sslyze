from typing import cast

from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.cli.output_generator import OutputGenerator

from sslyze.errors import ConnectionToServerFailed
from sslyze.plugins.scan_commands import ScanCommandsRepository, ScanCommandType
from sslyze.scanner import ServerScanResult, ScanCommandErrorReasonEnum
from sslyze.server_connectivity import ServerConnectivityInfo, ClientAuthRequirementEnum
from sslyze.server_setting import (
    ServerNetworkLocationViaDirectConnection,
    ServerNetworkLocationViaHttpProxy,
    ServerNetworkLocation,
)


class ConsoleOutputGenerator(OutputGenerator):
    @classmethod
    def _format_title(cls, title: str) -> str:
        return f" {title.upper()}\n {'-' * len(title)}\n"

    def command_line_parsed(self, parsed_command_line: ParsedCommandLine) -> None:
        self._file_to.write("\n")
        self._file_to.write(self._format_title("Checking host(s) availability"))
        self._file_to.write("\n")

        for bad_server_str in parsed_command_line.invalid_servers:
            self._file_to.write(
                f"   {bad_server_str.server_string:<35} => ERROR: {bad_server_str.error_message};"
                f" discarding scan.\n"
            )

    def server_connectivity_test_failed(self, connectivity_error: ConnectionToServerFailed) -> None:
        self._file_to.write(
            f"   {connectivity_error.server_location.hostname}:{connectivity_error.server_location.port:<25}"
            f" => ERROR: {connectivity_error.error_message}; discarding scan.\n"
        )

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        client_auth_msg = ""
        client_auth_requirement = server_connectivity_info.tls_probing_result.client_auth_requirement
        if client_auth_requirement == ClientAuthRequirementEnum.REQUIRED:
            client_auth_msg = "  WARNING: Server REQUIRED client authentication, specific plugins will fail."
        elif client_auth_requirement == ClientAuthRequirementEnum.OPTIONAL:
            client_auth_msg = "  WARNING: Server requested optional client authentication"

        server_location = server_connectivity_info.server_location
        network_route = _server_location_to_network_route(server_location)
        self._file_to.write(
            f"   {server_location.hostname}:{server_location.port:<25} => {network_route} {client_auth_msg}\n"
        )

    def scans_started(self) -> None:
        self._file_to.write("\n\n\n\n")

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        target_result_str = ""

        # Display the server that was scanned
        server_location = server_scan_result.server_info.server_location
        network_route = _server_location_to_network_route(server_location)

        # Display result for scan commands that were run successfully
        for scan_command, scan_command_result in server_scan_result.scan_commands_results.items():
            typed_scan_command = cast(ScanCommandType, scan_command)
            target_result_str += "\n"
            cli_connector_cls = ScanCommandsRepository.get_implementation_cls(typed_scan_command).cli_connector_cls
            for line in cli_connector_cls.result_to_console_output(scan_command_result):
                target_result_str += line + "\n"

        # Display scan commands that failed
        for scan_command, scan_command_error in server_scan_result.scan_commands_errors.items():
            target_result_str += "\n"
            cli_connector_cls = ScanCommandsRepository.get_implementation_cls(scan_command).cli_connector_cls

            if scan_command_error.reason == ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED:
                target_result_str += cli_connector_cls._format_title(
                    f"Client certificated required for --{cli_connector_cls._cli_option}"
                )
                target_result_str += " use --cert and --key to provide one.\n"

            elif scan_command_error.reason == ScanCommandErrorReasonEnum.CONNECTIVITY_ISSUE:
                target_result_str += cli_connector_cls._format_title(
                    f"Connection timed out for --{cli_connector_cls._cli_option}"
                )
                target_result_str += " try using --slow_connection to reduce the impact on the server.\n"

            elif scan_command_error.reason in [
                ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
                ScanCommandErrorReasonEnum.WRONG_USAGE,
            ]:
                target_result_str += cli_connector_cls._format_title(
                    f"Error when running --{cli_connector_cls._cli_option}"
                )
                target_result_str += "\n"
                target_result_str += (
                    "       You can open an issue at https://github.com/nabla-c0d3/sslyze/issues"
                    " with the following information:\n\n"
                )
                target_result_str += (
                    f"       * Server: {server_location.hostname}:{server_location.port} - {network_route}\n"
                )
                target_result_str += f"       * Scan command: {scan_command}\n\n"
                for line in scan_command_error.exception_trace.format(chain=False):
                    target_result_str += f"       {line}"
            else:
                raise ValueError("Should never happen")

        scan_txt = f"Scan Results For {server_location.hostname}:{server_location.port} - {network_route}"
        self._file_to.write(self._format_title(scan_txt) + target_result_str + "\n\n")

    def scans_completed(self, total_scan_time: float) -> None:
        self._file_to.write(self._format_title("Scan Completed in {0:.2f} s".format(total_scan_time)))


def _server_location_to_network_route(server_location: ServerNetworkLocation) -> str:
    if isinstance(server_location, ServerNetworkLocationViaDirectConnection):
        network_route = server_location.ip_address
    elif isinstance(server_location, ServerNetworkLocationViaHttpProxy):
        # We do not know the server's IP address if going through a proxy
        network_route = "HTTP proxy at {}:{}".format(
            server_location.http_proxy_settings.hostname, server_location.http_proxy_settings.port
        )
    else:
        raise ValueError("Should never happen")
    return network_route
