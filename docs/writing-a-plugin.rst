
Appendix: Writing Your Own Plugins
**********************************

Things that SSLyze can scan for are implemented using a plugin system. If you want to create a new plugin, the easiest
way to get started is to review a simple existing plugin such as the `CompressionPlugin` in
`sslyze.plugins.compression_plugin`.


High Level Overview
===================

A plugin is made of one `Plugin` subclass and one or multiple subclasses of `PluginScanCommand` and `PluginScanResult`.
The `Plugin` receives a `PluginScanCommand`, performs the corresponding scan, and returns a `PluginScanResult`.

For the `Plugin` to be discovered by SSLyze, it needs to be added to `sslyze.plugins.plugin_repository`.

Core parent classes
-------------------

.. module:: sslyze.plugins.plugin_base
.. autoclass:: Plugin
   :members: get_available_commands, process_task
.. autoclass:: PluginScanCommand
   :members: __init__, get_cli_argument, is_aggressive
.. autoclass:: PluginScanResult
   :noindex:
   :members: __init__, as_text, as_xml
