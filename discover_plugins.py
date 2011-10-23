#-------------------------------------------------------------------------------
# Name:         discover_plugins.py
# Purpose:      Finds available plugins.
#
# Author:       aaron, alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
# Licence:      Licensed under the terms of the GPLv2 License
#-------------------------------------------------------------------------------
#!/usr/bin/env python

import os
import inspect
from imp import load_module, find_module
import plugins

def discover_plugins(plugin_dir):
    """
    Opens the plugin_dir and looks at every .py module in that directory.
    Finds available plugins by looking at any class defined in those modules
    that implements the PluginBase abstract class.
    Returns a list of plugin classes.
    """
    plugins_found = set([])
    print''

    if os.path.exists(plugin_dir):
        for (root, dirs, files) in os.walk(plugin_dir):
            del dirs[:] # Do not walk into subfolders of the plugin directory
            # Checking every .py module in the plugin directory
            for source in (s for s in files if s.endswith(".py")):
                module_name = os.path.splitext(os.path.basename(source))[0]
                full_name = os.path.splitext(source)[0].replace(os.path.sep,'.')

                try: # Try to import the plugin package
                # The plugin package HAS to be imported as a submodule
                # of module 'plugins' or it will break windows compatibility
                    (file, pathname, description) = \
                        find_module(full_name, plugins.__path__)
                    module = load_module('plugins.' + full_name, file,
                                            pathname, description)
                except Exception as e:
                    print '   ' + module_name + ' - Import Error: ' + str(e)
                    continue

                # Check every declaration in that module
                for name in dir(module):
                    obj = getattr(module, name)
                    if inspect.isclass(obj):
                        # A class declaration was found in that module
                        # Checking if it's a subclass of PluginBase
                        # Discarding PluginBase as a subclass of PluginBase
                        if obj != plugins.PluginBase.PluginBase:
                            if issubclass(obj, plugins.PluginBase.PluginBase):
                                # A plugin was found, keep it
                                print '   ' + name + ' - OK'
                                plugins_found.add(obj)

    return list(plugins_found)
