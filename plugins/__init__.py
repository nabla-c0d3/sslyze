#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         __init__.py
# Purpose:      PluginsFinder class for the SSLyze plugins package.
#
# Author:       alban, aaron
#
# Copyright:    2012 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------


import os
import sys
import inspect
from imp import load_module, find_module
import importlib

import plugins
import plugins.PluginBase


class PluginsFinder:

    def __init__(self):
        """
        Opens the plugins folder and looks at every .py module in that directory.
        Finds available plugins by looking at any class defined in those modules
        that implements the PluginBase abstract class.
        Returns a list of plugin classes.
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
                    # A class declaration was found in that module
                    # Checking if it's a subclass of PluginBase
                    # Discarding PluginBase as a subclass of PluginBase
                    if obj != plugins.PluginBase.PluginBase:
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

        plugin_modules = []
        AVAILABLE_PLUGIN_NAMES = ['plugins.PluginCompression', 'plugins.PluginCertInfo', 'plugins.PluginHeartbleed',
                                  'plugins.PluginHSTS', 'plugins.PluginOpenSSLCipherSuites',
                                  'plugins.PluginSessionRenegotiation', 'plugins.PluginSessionResumption',
                                  'plugins.PluginChromeSha1Deprecation']

        # This it to ensure py2exe can find the plugins
        import plugins.PluginCompression
        import plugins.PluginCertInfo
        import plugins.PluginHeartbleed
        import plugins.PluginHSTS
        import plugins.PluginOpenSSLCipherSuites
        import plugins.PluginSessionRenegotiation
        import plugins.PluginSessionResumption
        import plugins.PluginChromeSha1Deprecation

        for plugin_name in AVAILABLE_PLUGIN_NAMES:
            imported_module = importlib.import_module(plugin_name)
            plugin_modules.append(imported_module)

        return plugin_modules


    @staticmethod
    def get_plugin_modules_dynamic():

        plugin_modules = []

        plugin_dir = plugins.__path__[0]
        full_plugin_dir = os.path.join(sys.path[0], plugin_dir)

        if os.path.exists(full_plugin_dir):
            for (root, dirs, files) in os.walk(full_plugin_dir):
                del dirs[:] # Do not walk into subfolders of the plugin directory
                # Checking every .py module in the plugin directory
                plugins_loaded = []
                for source in (s for s in files if s.endswith((".py"))):
                    module_name = os.path.splitext(os.path.basename(source))[0]
                    if module_name in plugins_loaded:
                        continue
                    plugins_loaded.append(module_name)
                    full_name = os.path.splitext(source)[0].replace(os.path.sep,'.')

                    try: # Try to import the plugin package
                    # The plugin package HAS to be imported as a submodule
                    # of module 'plugins' or it will break windows compatibility
                        (file, pathname, description) = \
                            find_module(full_name, plugins.__path__)
                        module = load_module('plugins.' + full_name, file,
                                                pathname, description)
                    except Exception as e:
                        print '  ' + module_name + ' - Import Error: ' + str(e)
                        continue

                    plugin_modules.append(module)

        return plugin_modules
