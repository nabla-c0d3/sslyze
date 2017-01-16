# -*- coding: utf-8 -*-

from __future__ import print_function


import sslyze.plugins
import sslyze.plugins.plugin_base
from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
from sslyze.plugins.compression_plugin import CompressionPlugin
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvPlugin
from sslyze.plugins.openssl_cipher_suites_plugin import OpenSslCipherSuitesPlugin


# TODO(ad): rename this
class PluginsFinder(object):
    """Utility class to discover the list of available SSLyze scanning plugins and commands.
    """

    _DISCOVERED_PLUGINS = None

    @classmethod
    def get(cls):
        # type: () -> PluginsFinder
        """Discover available SSLyze plugins and return a PluginsFinder to be passed to a PluginsProcessPool.

        Returns:
            PluginsFinder:  An object encapsulating the list of available SSLyze plugins.
        """
        if cls._DISCOVERED_PLUGINS is None:
            cls._DISCOVERED_PLUGINS = PluginsFinder()
        return cls._DISCOVERED_PLUGINS


    def __init__(self):
        # type: () -> None
        """Find available plugins by discovering any class that implements the PluginBase abstract class.

        Returns:
            PluginsFinder:  An object encapsulating the list of available SSLyze plugins.
        """
        self._plugin_classes = [OpenSslCipherSuitesPlugin, CertificateInfoPlugin, CompressionPlugin, FallbackScsvPlugin]
        self._commands = []
        for plugin_class in self._plugin_classes:
            self._commands.extend(plugin_class.get_available_commands())


    def get_plugins(self):
        return self._plugin_classes


    def get_commands(self):
        return self._commands

    @staticmethod
    def get_plugin_modules_static():

        import sslyze.plugins.certificate_info_plugin
        import sslyze.plugins.compression_plugin
        import sslyze.plugins.fallback_scsv_plugin
        import sslyze.plugins.heartbleed_plugin
        import sslyze.plugins.http_headers_plugin
        import sslyze.plugins.openssl_ccs_injection_plugin
        import sslyze.plugins.openssl_cipher_suites_plugin
        import sslyze.plugins.session_renegotiation_plugin
        import sslyze.plugins.session_resumption_plugin

        plugin_modules = [
            sslyze.plugins.certificate_info_plugin,
            sslyze.plugins.compression_plugin,
            sslyze.plugins.fallback_scsv_plugin,
            sslyze.plugins.heartbleed_plugin,
            sslyze.plugins.http_headers_plugin,
            sslyze.plugins.openssl_ccs_injection_plugin,
            sslyze.plugins.openssl_cipher_suites_plugin,
            sslyze.plugins.session_renegotiation_plugin,
            sslyze.plugins.session_resumption_plugin
        ]

        return plugin_modules


    @staticmethod
    def get_plugin_modules_dynamic():
        plugin_modules = []
        import pkgutil
        for loader, module_name, _ in list(pkgutil.iter_modules(sslyze.plugins.__path__, prefix='sslyze.plugins.')):
            try:
                module = loader.find_module(module_name).load_module(module_name)
                plugin_modules.append(module)
            except Exception as e:
                print('  {module} - Import Error: {error}'.format(module=module_name, error=str(e)))
                continue

        return plugin_modules
