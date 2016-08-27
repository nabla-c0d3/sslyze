# -*- coding: utf-8 -*-
"""Utility class to discover the list of available plugins.
"""

import importlib
import inspect
import sys
import sslyze.plugins
import sslyze.plugins.plugin_base


class PluginsFinder:

    def __init__(self):
        """Finds available plugins by discovering any class that implements the PluginBase abstract class.

        Returns PluginsFinder: An object encapsulating the list of available sslyze plugin classess.
        """
        self._plugin_classes = set([])
        self._commands = {}
        self._aggressive_comands = []


        if hasattr(sys,"frozen") and sys.frozen in ("windows_exe", "console_exe"):
            # For py2exe builds we have to load the plugins statically using a hardcoded list
            plugin_modules = self.get_plugin_modules_static()
        else:
            # When ran from the interpreter, just dynamically find the available plugins
            plugin_modules = self.get_plugin_modules_dynamic()

        for module in plugin_modules:
            # Check every declaration in that module
            for name in dir(module):
                obj = getattr(module, name)

                if inspect.isclass(obj):
                    # A class declaration was found in that module; checking if it's a subclass of PluginBase
                    # Discarding PluginBase as a subclass of PluginBase
                    if obj != sslyze.plugins.plugin_base.PluginBase:
                        for base in obj.__bases__:
                            # H4ck because issubclass() doesn't seem to work as expected on Linux
                            # It has to do with PluginBase being imported multiple times (within plugins) or something
                            if base.__name__ == 'PluginBase':
                                # A plugin was found, keep it
                                self._plugin_classes.add(obj)

                        #if issubclass(obj, plugins.PluginBase.PluginBase):
                            # A plugin was found, keep it
                        #    self._plugin_classes.add(obj)

                                # Store the plugin's commands
                                for (cmd, is_aggressive) in obj.get_interface().get_commands_as_text():
                                    self._commands[cmd] = obj
                                    # Store a list of aggressive commands
                                    if is_aggressive:
                                        self._aggressive_comands.append(cmd)



    def get_plugins(self):
        return self._plugin_classes


    def get_commands(self):
        return self._commands


    def get_aggressive_commands(self):
        return self._aggressive_comands


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
                print '  {module} - Import Error: {error}'.format(module=module_name, error=str(e))
                continue

        return plugin_modules
