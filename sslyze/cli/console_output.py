from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.cli.output_generator import OutputGenerator

from sslyze.connection_helpers.errors import ConnectionToServerFailed
from sslyze.scanner import ServerScanResult
from sslyze.server_connectivity import ServerConnectivityInfo, ClientAuthRequirementEnum
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection, ServerNetworkLocationViaHttpProxy


class ConsoleOutputGenerator(OutputGenerator):

    TITLE_FORMAT = " {title}\n {underline}\n"

    SERVER_OK_FORMAT = "   {host}:{port:<25} => {network_route} {client_auth_msg}\n"

    # The server string (host:port) supplied via teh command line was malformed
    SERVER_STR_INVALID_FORMAT = "   {server_string:<35} => WARNING: {error_msg}; discarding corresponding tasks.\n"

    # Connectivity testing with this server failed
    SERVER_ERROR_FORMAT = "   {host}:{port:<25} => WARNING: {error_msg}; discarding corresponding tasks.\n"

    SCAN_FORMAT = "Scan Results For {0}:{1} - {2}"

    @classmethod
    def _format_title(cls, title: str) -> str:
        return cls.TITLE_FORMAT.format(title=title.upper(), underline="-" * len(title))

    def command_line_parsed(self, parsed_command_line: ParsedCommandLine) -> None:
        self._file_to.write("\n")
        self._file_to.write(self._format_title("Checking host(s) availability"))
        self._file_to.write("\n")

        for bad_server_str in parsed_command_line.invalid_servers:
            self._file_to.write(
                self.SERVER_STR_INVALID_FORMAT.format(
                    server_string=bad_server_str.server_string, error_msg=bad_server_str.error_message
                )
            )

    def server_connectivity_test_failed(self, connectivity_error: ConnectionToServerFailed) -> None:
        self._file_to.write(
            self.SERVER_ERROR_FORMAT.format(
                host=connectivity_error.server_location.hostname,
                port=connectivity_error.server_location.port,
                error_msg=connectivity_error.error_message,
            )
        )

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        client_auth_msg = ""
        client_auth_requirement = server_connectivity_info.tls_probing_result.client_auth_requirement
        if client_auth_requirement == ClientAuthRequirementEnum.REQUIRED:
            client_auth_msg = "  WARNING: Server REQUIRED client authentication, specific plugins will fail."
        elif client_auth_requirement == ClientAuthRequirementEnum.OPTIONAL:
            client_auth_msg = "  WARNING: Server requested optional client authentication"

        server_location = server_connectivity_info.server_location
        if isinstance(server_location , ServerNetworkLocationViaDirectConnection):
            network_route = server_location.ip_address
        elif isinstance(server_location , ServerNetworkLocationViaHttpProxy):
            # We do not know the server's IP address if going through a proxy
            network_route = "HTTP proxy at {}:{}".format(
                server_location.http_proxy_settings.hostname,
                server_location.http_proxy_settings.port,
            )
        else:
            raise ValueError("Should never happen")

        self._file_to.write(
            self.SERVER_OK_FORMAT.format(
                host=server_location.hostname,
                port=server_location.port,
                network_route=network_route,
                client_auth_msg=client_auth_msg,
            )
        )

    def scans_started(self) -> None:
        self._file_to.write("\n\n\n\n")

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        target_result_str = ""
        for scan_command, scan_command_result in server_scan_result.scan_commands_results.items():
            cli_connector_cls = scan_command._get_implementation_cls().cli_connector_cls
            # Print the result of each separate command
            target_result_str += "\n"
            for line in cli_connector_cls.result_to_console_output(scan_command_result):
                target_result_str += line + "\n"

        server_location = server_scan_result.server_info.server_location
        if isinstance(server_location , ServerNetworkLocationViaDirectConnection):
            network_route = server_location.ip_address
        elif isinstance(server_location , ServerNetworkLocationViaHttpProxy):
            # We do not know the server's IP address if going through a proxy
            network_route = "HTTP proxy at {}:{}".format(
                server_location.http_proxy_settings.hostname,
                server_location.http_proxy_settings.port,
            )
        else:
            raise ValueError("Should never happen")

        scan_txt = self.SCAN_FORMAT.format(
            server_location.hostname, str(server_location.port), network_route
        )
        self._file_to.write(self._format_title(scan_txt) + target_result_str + "\n\n")

    def scans_completed(self, total_scan_time: float) -> None:
        self._file_to.write(self._format_title("Scan Completed in {0:.2f} s".format(total_scan_time)))
