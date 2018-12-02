from xml.etree.ElementTree import Element
from nassl.ssl_client import ClientCertificateRequested, OpenSslVersionEnum
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.server_connectivity_info import ServerConnectivityInfo
from typing import Type, List

from sslyze.utils.ssl_connection import SslHandshakeRejected


class CompressionScanCommand(PluginScanCommand):
    """Test the server(s) for Zlib compression support.
    """

    @classmethod
    def get_cli_argument(cls) -> str:
        return 'compression'

    @classmethod
    def get_title(cls) -> str:
        return 'Deflate Compression'


class CompressionPlugin(plugin_base.Plugin):
    """Test the server(s) for Zlib compression support.
    """

    @classmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        return [CompressionScanCommand]

    def process_task(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: PluginScanCommand
    ) -> 'CompressionScanResult':
        if not isinstance(scan_command, CompressionScanCommand):
            raise ValueError('Unexpected scan command')

        # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no compression with TLS 1.3
        if server_info.highest_ssl_version_supported >= OpenSslVersionEnum.TLSV1_3:
            ssl_version_to_use = OpenSslVersionEnum.TLSV1_2
        else:
            ssl_version_to_use = server_info.highest_ssl_version_supported

        ssl_connection = server_info.get_preconfigured_ssl_connection(
            override_ssl_version=ssl_version_to_use, should_use_legacy_openssl=True
        )

        # Make sure OpenSSL was built with support for compression to avoid false negatives
        if 'zlib compression' not in ssl_connection.ssl_client.get_available_compression_methods():
            raise RuntimeError(
                'OpenSSL was not built with support for zlib / compression. Did you build nassl yourself ?'
            )

        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            compression_name = ssl_connection.ssl_client.get_current_compression_method()
        except ClientCertificateRequested:
            # The server asked for a client cert
            compression_name = ssl_connection.ssl_client.get_current_compression_method()
        except SslHandshakeRejected:
            # Should only happen when the server only supports TLS 1.3, which does not support compression
            compression_name = ''
        finally:
            ssl_connection.close()

        return CompressionScanResult(server_info, scan_command, compression_name)


class CompressionScanResult(PluginScanResult):
    """The result of running a CompressionScanCommand on a specific server.

    Attributes:
        compression_name (str): The name of the compression algorithm supported by the server. `None` if
            compression is not supported by the server.
    """

    def __init__(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: CompressionScanCommand,
            compression_name: str
    ) -> None:
        super().__init__(server_info, scan_command)
        self.compression_name = compression_name

    def as_text(self) -> List[str]:
        txt_result = [self._format_title(self.scan_command.get_title())]
        if self.compression_name:
            txt_result.append(self._format_field('', 'VULNERABLE - Server supports Deflate compression'))
        else:
            txt_result.append(self._format_field('', 'OK - Compression disabled'))
        return txt_result

    def as_xml(self) -> Element:
        xml_result = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())
        if self.compression_name:
            xml_result.append(Element('compressionMethod', type="DEFLATE", isSupported="True"))
        else:
            xml_result.append(Element('compressionMethod', type="DEFLATE", isSupported="False"))
        return xml_result
