from typing import List, Type
from xml.etree.ElementTree import Element

from nassl._nassl import OpenSSLError
from nassl.ssl_client import OpenSslVersionEnum, OpenSslEarlyDataStatusEnum

from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanCommand, PluginScanResult
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.utils.http_request_generator import HttpRequestGenerator
from sslyze.utils.ssl_connection import SslHandshakeRejected


class EarlyDataScanCommand(PluginScanCommand):
    """Test the server(s) for TLS 1.3 early data support.
    """

    @classmethod
    def get_cli_argument(cls) -> str:
        return 'early_data'

    @classmethod
    def get_title(cls) -> str:
        return 'TLS 1.3 Early Data'


class EarlyDataPlugin(plugin_base.Plugin):
    """Test the server(s) for TLS 1.3 early data support.

    This plugin will only work for HTTPS servers; other TLS servers (SMTP, POP3, etc.) are not supported.
    """

    @classmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        return [EarlyDataScanCommand]

    def process_task(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: PluginScanCommand
    ) -> 'EarlyDataScanResult':
        if not isinstance(scan_command, EarlyDataScanCommand):
            raise ValueError('Unexpected scan command')

        session = None
        is_early_data_supported = False
        ssl_connection = server_info.get_preconfigured_ssl_connection(override_ssl_version=OpenSslVersionEnum.TLSV1_3)
        try:
            # Perform an SSL handshake and keep the session
            ssl_connection.connect()
            # Send and receive data for the TLS session to be created
            ssl_connection.ssl_client.write(HttpRequestGenerator.get_request(host=server_info.hostname))
            ssl_connection.ssl_client.read(2048)
            session = ssl_connection.ssl_client.get_session()
        except SslHandshakeRejected:
            # TLS 1.3 not supported
            is_early_data_supported = False
        finally:
            ssl_connection.close()

        # Then try to re-use the session and send early data
        if session is not None:
            ssl_connection2 = server_info.get_preconfigured_ssl_connection(
                override_ssl_version=OpenSslVersionEnum.TLSV1_3
            )
            ssl_connection2.ssl_client.set_session(session)

            try:
                # Open a socket to the server but don't do the handshake
                ssl_connection2.do_pre_handshake(None)

                # Send one byte of early data
                ssl_connection2.ssl_client.write_early_data(b'E')
                ssl_connection2.ssl_client.do_handshake()
                if ssl_connection2.ssl_client.get_early_data_status() == OpenSslEarlyDataStatusEnum.ACCEPTED:
                    is_early_data_supported = True
                else:
                    is_early_data_supported = False

            except OpenSSLError as e:
                if 'function you should not call' in e.args[0]:
                    # This is what OpenSSL returns when the server did not enable early data
                    is_early_data_supported = False
                else:
                    raise

            finally:
                ssl_connection2.close()

        return EarlyDataScanResult(server_info, scan_command, is_early_data_supported)


class EarlyDataScanResult(PluginScanResult):
    """The result of running an EarlyDataScanCommand on a specific server.

    Attributes:
        is_early_data_supported (bool): True if the server accepted early data.
    """

    def __init__(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: EarlyDataScanCommand,
            is_early_data_supported: bool,
    ) -> None:
        super().__init__(server_info, scan_command)
        self.is_early_data_supported = is_early_data_supported

    def as_text(self) -> List[str]:
        txt_result = [self._format_title(self.scan_command.get_title())]
        if self.is_early_data_supported:
            txt_result.append(self._format_field('', 'Suppported - Server accepted early data'))
        else:
            txt_result.append(self._format_field('', 'Not Supported'))
        return txt_result

    def as_xml(self) -> Element:
        xml_result = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())
        xml_result.append(Element('earlyData', isSupported=str(self.is_early_data_supported)))
        return xml_result
