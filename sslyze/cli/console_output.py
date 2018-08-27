from sslyze.cli import CompletedServerScan
from sslyze.cli.command_line_parser import ServerStringParsingError
from sslyze.cli.output_generator import OutputGenerator
from sslyze.plugins.plugin_base import Plugin
from sslyze.server_connectivity_tester import ServerConnectivityError
from sslyze.ssl_settings import ClientAuthenticationServerConfigurationEnum
from sslyze.server_connectivity_info import ServerConnectivityInfo
from typing import Type, Set, Any, List


class ConsoleOutputGenerator(OutputGenerator):

    TITLE_FORMAT = ' {title}\n {underline}\n'

    SERVER_OK_FORMAT = '   {host}:{port:<25} => {network_route} {client_auth_msg}\n'

    # The server string (host:port) supplied via teh command line was malformed
    SERVER_STR_INVALID_FORMAT = '   {server_string:<35} => WARNING: {error_msg}; discarding corresponding tasks.\n'

    # Connectivity testing with this server failed
    SERVER_ERROR_FORMAT = '   {host}:{port:<25} => WARNING: {error_msg}; discarding corresponding tasks.\n'

    SCAN_FORMAT = 'Scan Results For {0}:{1} - {2}'

    @classmethod
    def _format_title(cls, title: str) -> str:
        return cls.TITLE_FORMAT.format(title=title.upper(), underline='-' * len(title))

    def command_line_parsed(
            self,
            available_plugins: Set[Type[Plugin]],
            args_command_list: Any,
            malformed_servers: List[ServerStringParsingError]
    ) -> None:
        self._file_to.write('\n\n\n' + self._format_title('Available plugins'))
        self._file_to.write('\n')
        for plugin in available_plugins:
            self._file_to.write('  {}\n'.format(plugin.__name__))
        self._file_to.write('\n\n\n')

        self._file_to.write(self._format_title('Checking host(s) availability'))
        self._file_to.write('\n')

        for bad_server_str in malformed_servers:
            self._file_to.write(self.SERVER_STR_INVALID_FORMAT.format(server_string=bad_server_str.server_string,
                                                                      error_msg=bad_server_str.error_message))

    def server_connectivity_test_failed(self, connectivity_error: ServerConnectivityError) -> None:
        self._file_to.write(self.SERVER_ERROR_FORMAT.format(host=connectivity_error.server_info.hostname,
                                                            port=connectivity_error.server_info.port,
                                                            error_msg=connectivity_error.error_message))

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        client_auth_msg = ''
        client_auth_requirement = server_connectivity_info.client_auth_requirement
        if client_auth_requirement == ClientAuthenticationServerConfigurationEnum.REQUIRED:
            client_auth_msg = '  WARNING: Server REQUIRED client authentication, specific plugins will fail.'
        elif client_auth_requirement == ClientAuthenticationServerConfigurationEnum.OPTIONAL:
            client_auth_msg = '  WARNING: Server requested optional client authentication'

        network_route = server_connectivity_info.ip_address
        if server_connectivity_info.http_tunneling_settings:
            # We do not know the server's IP address if going through a proxy
            network_route = 'Proxy at {}:{}'.format(
                server_connectivity_info.http_tunneling_settings.hostname,
                server_connectivity_info.http_tunneling_settings.port
            )

        self._file_to.write(self.SERVER_OK_FORMAT.format(host=server_connectivity_info.hostname,
                                                         port=server_connectivity_info.port,
                                                         network_route=network_route,
                                                         client_auth_msg=client_auth_msg))

    def scans_started(self) -> None:
        self._file_to.write('\n\n\n\n')

    def server_scan_completed(self, server_scan: CompletedServerScan) -> None:
        target_result_str = ''
        for plugin_result in server_scan.plugin_result_list:
            # Print the result of each separate command
            target_result_str += '\n'
            for line in plugin_result.as_text():
                target_result_str += line + '\n'

        network_route = server_scan.server_info.ip_address
        if server_scan.server_info.http_tunneling_settings:
            # We do not know the server's IP address if going through a proxy
            network_route = 'Proxy at {}:{}'.format(
                server_scan.server_info.http_tunneling_settings.hostname,
                server_scan.server_info.http_tunneling_settings.port
            )

        scan_txt = self.SCAN_FORMAT.format(server_scan.server_info.hostname, str(server_scan.server_info.port),
                                           network_route)
        self._file_to.write(self._format_title(scan_txt) + target_result_str + '\n\n')

    def scans_completed(self, total_scan_time: float) -> None:
        self._file_to.write(self._format_title('Scan Completed in {0:.2f} s'.format(total_scan_time)))
