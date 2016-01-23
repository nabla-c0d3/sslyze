import importlib
import inspect
import sys
import sslyze.plugins
import sslyze.plugins.PluginBase


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
                if name not in module.__name__:
                    # Plugins have to have the same class name as their module name
                    # This prevents Plugin B from being detected twice when there is a Plugin A that imports Plugin B
                    continue

                if inspect.isclass(obj):
                    # A class declaration was found in that module
                    # Checking if it's a subclass of PluginBase
                    # Discarding PluginBase as a subclass of PluginBase
                    if obj != sslyze.plugins.PluginBase.PluginBase:
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
        AVAILABLE_PLUGIN_NAMES = ['sslyze.plugins.PluginCompression',
                                  'sslyze.plugins.PluginCertInfo',
                                  'sslyze.plugins.PluginHeartbleed',
                                  'sslyze.plugins.PluginHSTS',
                                  'sslyze.plugins.PluginOpenSSLCipherSuites',
                                  'sslyze.plugins.PluginSessionRenegotiation',
                                  'sslyze.plugins.PluginSessionResumption',
                                  'sslyze.plugins.PluginChromeSha1Deprecation',
                                  'sslyze.plugins.PluginOpenSSLProtocolSupport']  # TODO: Add new plugins

        # This it to ensure py2exe can find the plugins
        import sslyze.plugins.PluginSessionResumption

        for plugin_name in AVAILABLE_PLUGIN_NAMES:
            imported_module = importlib.import_module(plugin_name)
            plugin_modules.append(imported_module)

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
