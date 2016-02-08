# -*- coding: utf-8 -*-
"""Plugin to test the server for the TLS_FALLBACK_SCSV cipher suite, which prevents downgrade attacks.
"""

from xml.etree.ElementTree import Element
from nassl import SSLV3, SSL_MODE_SEND_FALLBACK_SCSV, _nassl
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginResult
from sslyze.utils.ssl_connection import SSLHandshakeRejected


class FallbackScsvPlugin(plugin_base.PluginBase):

    interface = plugin_base.PluginInterface(title="FallbackScsvPlugin", description="")
    interface.add_command(
        command="fallback",
        help="Checks support for the TLS_FALLBACK_SCSV cipher suite to prevent downgrade attacks."
    )


    def process_task(self, server_info, plugin_command, plugin_options=None):
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

        return FallbackScsvResult(server_info, plugin_command, plugin_options, supports_fallback_scsv)


class FallbackScsvResult(PluginResult):
    """The result of running --fallback on a specific server.

    Attributes:
        supports_fallback_scsv (bool): True if the server supports the TLS_FALLBACK_SCSV mechanism to block downgrade
        attacks.
    """

    COMMAND_TITLE = 'Downgrade Attacks'

    def __init__(self, server_info, plugin_command, plugin_options, supports_fallback_scsv):
        super(FallbackScsvResult, self).__init__(server_info, plugin_command, plugin_options)
        self.supports_fallback_scsv = supports_fallback_scsv

    def as_text(self):
        result_txt = [self.PLUGIN_TITLE_FORMAT(self.COMMAND_TITLE)]
        downgrade_txt = 'OK - Supported' \
            if self.supports_fallback_scsv \
            else 'VULNERABLE - Signaling cipher suite not supported'
        result_txt.append(self.FIELD_FORMAT('TLS_FALLBACK_SCSV:', downgrade_txt))
        return result_txt

    def as_xml(self):
        result_xml = Element(self.plugin_command, title=self.COMMAND_TITLE)
        result_xml.append(Element('tlsFallbackScsv', attrib={'isSupported': str(self.supports_fallback_scsv)}))
        return result_xml
