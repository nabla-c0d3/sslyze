# -*- coding: utf-8 -*-


from xml.etree.ElementTree import Element
from nassl import SSLV3, SSL_MODE_SEND_FALLBACK_SCSV, _nassl
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginResult, ScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SSLHandshakeRejected


class FallbackScsvScanCommand(ScanCommand):
    """Test for support of the TLS_FALLBACK_SCSV cipher suite which prevents downgrade attacks.
    """

    @classmethod
    def get_cli_argument(cls):
        return u'fallback'

    @classmethod
    def get_plugin_class(cls):
        return FallbackScsvPlugin


class FallbackScsvPlugin(plugin_base.Plugin):
    """Test for support of the TLS_FALLBACK_SCSV cipher suite which prevents downgrade attacks.
    """

    @classmethod
    def get_available_commands(cls):
        return [FallbackScsvScanCommand]

    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, FallbackScsvScanCommand) -> FallbackScsvResult
        if server_info.highest_ssl_version_supported <= SSLV3:
            raise ValueError('Server only supports SSLv3; no downgrade attacks are possible')

        # Try to connect using a lower TLS version with the fallback cipher suite enabled
        ssl_version_downgrade = server_info.highest_ssl_version_supported - 1
        ssl_connection = server_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version_downgrade)
        ssl_connection.set_mode(SSL_MODE_SEND_FALLBACK_SCSV)

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

        except SSLHandshakeRejected:
            # If the handshake is rejected, we assume downgrade attacks are prevented (this is how F5 balancers do it)
            # although it could also be because the server does not support this version of TLS
            # https://github.com/nabla-c0d3/sslyze/issues/119
            supports_fallback_scsv = True

        finally:
            ssl_connection.close()

        return FallbackScsvResult(server_info, scan_command, supports_fallback_scsv)


class FallbackScsvResult(PluginResult):
    """The result of running --fallback on a specific server.

    Attributes:
        supports_fallback_scsv (bool): True if the server supports the TLS_FALLBACK_SCSV mechanism to block downgrade
        attacks.
    """

    COMMAND_TITLE = u'Downgrade Attacks'

    def __init__(self, server_info, scan_command, supports_fallback_scsv):
        # type: (ServerConnectivityInfo, FallbackScsvScanCommand, bool) -> None
        super(FallbackScsvResult, self).__init__(server_info, scan_command)
        self.supports_fallback_scsv = supports_fallback_scsv

    def as_text(self):
        result_txt = [self._format_title(self.COMMAND_TITLE)]
        downgrade_txt = u'OK - Supported' \
            if self.supports_fallback_scsv \
            else u'VULNERABLE - Signaling cipher suite not supported'
        result_txt.append(self._format_field(u'TLS_FALLBACK_SCSV:', downgrade_txt))
        return result_txt

    def as_xml(self):
        result_xml = Element(self.scan_command.get_cli_argument(), title=self.COMMAND_TITLE)
        result_xml.append(Element('tlsFallbackScsv', attrib={'isSupported': str(self.supports_fallback_scsv)}))
        return result_xml
