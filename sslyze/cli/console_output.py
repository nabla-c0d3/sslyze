from sslyze.cli import CompletedServerScan
from sslyze.cli import FailedServerScan
from sslyze.cli.output_generator import OutputGenerator
from sslyze.server_connectivity import ClientAuthenticationServerConfigurationEnum
from sslyze.server_connectivity import ServerConnectivityInfo
from typing import Text


class ConsoleOutputGenerator(OutputGenerator):

    TITLE_FORMAT = u' {title}\n {underline}\n'

    SERVER_OK_FORMAT = u'   {host}:{port:<25} => {network_route} {client_auth_msg}'
    SERVER_INVALID_FORMAT = u'   {server_string:<35} => WARNING: {error_msg}; discarding corresponding tasks.'

    SCAN_FORMAT = u'Scan Results For {0}:{1} - {2}'


    @classmethod
    def _format_title(cls, title):
        # type: (Text) -> Text
        return cls.TITLE_FORMAT.format(title=title.upper(), underline='-' * len(title))


    def command_line_parsed(self, available_plugins, args_command_list):
        self._file_to.write('\n\n\n' + self._format_title(u'Available plugins'))
        self._file_to.write('\n')
        for plugin in available_plugins:
            self._file_to.write('  {}\n'.format(plugin.__name__))
        self._file_to.write('\n\n\n')

        self._file_to.write(self._format_title(u'Checking host(s) availability'))
        self._file_to.write('\n')


    def server_connectivity_test_failed(self, failed_scan):
        # type: (FailedServerScan) -> None
        self._file_to.write(self.SERVER_INVALID_FORMAT.format(server_string=failed_scan.server_string,
                                                              error_msg=failed_scan.error_message))


    def server_connectivity_test_succeeded(self, server_connectivity_info):
        # type: (ServerConnectivityInfo) -> None
        client_auth_msg = u''
        client_auth_requirement = server_connectivity_info.client_auth_requirement
        if client_auth_requirement == ClientAuthenticationServerConfigurationEnum.REQUIRED:
            client_auth_msg = u'  WARNING: Server REQUIRED client authentication, specific plugins will fail.'
        elif client_auth_requirement == ClientAuthenticationServerConfigurationEnum.OPTIONAL:
            client_auth_msg = u'  WARNING: Server requested optional client authentication'

        network_route = server_connectivity_info.ip_address
        if server_connectivity_info.http_tunneling_settings:
            # We do not know the server's IP address if going through a proxy
            network_route = u'Proxy at {}:{}'.format(server_connectivity_info.http_tunneling_settings.hostname,
                                                     server_connectivity_info.http_tunneling_settings.port)

        self._file_to.write(self.SERVER_OK_FORMAT.format(host=server_connectivity_info.hostname,
                                                         port=server_connectivity_info.port,
                                                         network_route=network_route,
                                                         client_auth_msg=client_auth_msg))

    def scans_started(self):
        self._file_to.write('\n\n\n\n')


    def server_scan_completed(self, server_scan):
        # type: (CompletedServerScan) -> None
        target_result_str = u''
        for plugin_result in server_scan.plugin_result_list:
            # Print the result of each separate command
            target_result_str += '\n'
            for line in plugin_result.as_text():
                target_result_str += line + '\n'


        network_route = server_scan.server_info.ip_address
        if server_scan.server_info.http_tunneling_settings:
            # We do not know the server's IP address if going through a proxy
            network_route = u'Proxy at {}:{}'.format(server_scan.server_info.http_tunneling_settings.hostname,
                                                     server_scan.server_info.http_tunneling_settings.port)

        scan_txt = self.SCAN_FORMAT.format(server_scan.server_info.hostname, str(server_scan.server_info.port),
                                           network_route)
        self._file_to.write(self._format_title(scan_txt) + target_result_str + '\n\n')


    def scans_completed(self, total_scan_time):
        # type: (float) -> None
        self._file_to.write(self._format_title(u'Scan Completed in {0:.2f} s'.format(total_scan_time)))
