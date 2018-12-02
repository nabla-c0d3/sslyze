from typing import Type, List
from xml.etree.ElementTree import Element
from nassl import _nassl
from nassl.ssl_client import OpenSslVersionEnum
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SslHandshakeRejected


class FallbackScsvScanCommand(PluginScanCommand):
    """Test the server(s) for support of the TLS_FALLBACK_SCSV cipher suite which prevents downgrade attacks.
    """

    @classmethod
    def get_cli_argument(cls) -> str:
        return 'fallback'

    @classmethod
    def get_title(cls) -> str:
        return 'Downgrade Attacks'


class FallbackScsvPlugin(plugin_base.Plugin):
    """Test the server(s) for support of the TLS_FALLBACK_SCSV cipher suite which prevents downgrade attacks.
    """

    @classmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        return [FallbackScsvScanCommand]

    def process_task(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: PluginScanCommand
    ) -> 'FallbackScsvScanResult':
        if not isinstance(scan_command, FallbackScsvScanCommand):
            raise ValueError('Unexpected scan command')

        if server_info.highest_ssl_version_supported.value <= OpenSslVersionEnum.SSLV3.value:
            raise ValueError('Server only supports SSLv3; no downgrade attacks are possible')

        # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no downgrade possible with TLS 1.3
        if server_info.highest_ssl_version_supported >= OpenSslVersionEnum.TLSV1_3:
            ssl_version_to_use = OpenSslVersionEnum.TLSV1_2
        else:
            ssl_version_to_use = server_info.highest_ssl_version_supported

        # Try to connect using a lower TLS version with the fallback cipher suite enabled
        ssl_version_downgrade = OpenSslVersionEnum(ssl_version_to_use.value - 1)  # type: ignore
        ssl_connection = server_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version_downgrade)
        ssl_connection.ssl_client.enable_fallback_scsv()

        supports_fallback_scsv = False
        try:
            # Perform the SSL handshake
            ssl_connection.connect()

        except _nassl.OpenSSLError as e:
            # This is the right, specific alert the server should return
            if 'tlsv1 alert inappropriate fallback' in str(e.args):
                supports_fallback_scsv = True
            else:
                raise

        except SslHandshakeRejected:
            # If the handshake is rejected, we assume downgrade attacks are prevented (this is how F5 balancers do it)
            # although it could also be because the server does not support this version of TLS
            # https://github.com/nabla-c0d3/sslyze/issues/119
            supports_fallback_scsv = True

        finally:
            ssl_connection.close()

        return FallbackScsvScanResult(server_info, scan_command, supports_fallback_scsv)


class FallbackScsvScanResult(PluginScanResult):
    """The result of running a FallbackScsvScanCommand on a specific server.

    Attributes:
        supports_fallback_scsv (bool): True if the server supports the TLS_FALLBACK_SCSV mechanism to block downgrade
            attacks.
    """

    def __init__(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: FallbackScsvScanCommand,
            supports_fallback_scsv: bool
    ) -> None:
        super().__init__(server_info, scan_command)
        self.supports_fallback_scsv = supports_fallback_scsv

    def as_text(self) -> List[str]:
        result_txt = [self._format_title(self.scan_command.get_title())]
        downgrade_txt = 'OK - Supported' \
            if self.supports_fallback_scsv \
            else 'VULNERABLE - Signaling cipher suite not supported'
        result_txt.append(self._format_field('TLS_FALLBACK_SCSV:', downgrade_txt))
        return result_txt

    def as_xml(self) -> Element:
        result_xml = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())
        result_xml.append(Element('tlsFallbackScsv', attrib={'isSupported': str(self.supports_fallback_scsv)}))
        return result_xml
