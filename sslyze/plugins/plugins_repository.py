# -*- coding: utf-8 -*-

from __future__ import print_function

from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
from sslyze.plugins.compression_plugin import CompressionPlugin
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvPlugin
from sslyze.plugins.heartbleed_plugin import HeartbleedPlugin
from sslyze.plugins.http_headers_plugin import HttpHeadersPlugin
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionPlugin
from sslyze.plugins.openssl_cipher_suites_plugin import OpenSslCipherSuitesPlugin
from sslyze.plugins.plugin_base import Plugin
from sslyze.plugins.plugin_base import ScanCommand

from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationPlugin
from sslyze.plugins.session_resumption_plugin import SessionResumptionPlugin
from typing import List
from typing import Optional
from typing import Type


class PluginsRepository(object):
    """An object encapsulating the list of available SSLyze plugins.
    """

    _PLUGIN_CLASSES = [OpenSslCipherSuitesPlugin, CertificateInfoPlugin, CompressionPlugin, FallbackScsvPlugin,
                       HeartbleedPlugin, HttpHeadersPlugin, OpenSslCcsInjectionPlugin, SessionRenegotiationPlugin,
                       SessionResumptionPlugin]

    def __init__(self, plugin_classes=_PLUGIN_CLASSES):
        # type: (Optional[List[Type[Plugin]]]) -> None
        scan_commands_to_plugin_classes = {}

        # Create a dict of scan_commands -> plugin_classes
        for plugin_class in plugin_classes:
            for scan_command in plugin_class.get_available_commands():

                if scan_command in scan_commands_to_plugin_classes.keys():
                    raise KeyError(u'Found duplicate scan command: {}'.format(scan_command))
                scan_commands_to_plugin_classes[scan_command] = plugin_class

        self._scan_commands_to_plugin_classes = scan_commands_to_plugin_classes

    def get_plugin_class_for_command(self, scan_command):
        # type: (ScanCommand) -> Type[Plugin]
        """Get the class of the plugin implementing the supplied scan command.
        """
        return self._scan_commands_to_plugin_classes[scan_command.__class__]

    def get_available_commands(self):
        # type: () -> List[ScanCommand]
        """Get the list of all available scan comands across all plugins.
        """
        return self._scan_commands_to_plugin_classes.keys()

    def get_available_plugins(self):
        # type: () -> List[Type[Plugin]]
        """Get the list of all available plugin.
        """
        return list(set(self._scan_commands_to_plugin_classes.values()))
