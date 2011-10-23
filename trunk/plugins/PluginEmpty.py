#-------------------------------------------------------------------------------
# Name:         PluginEmpty.py
# Purpose:      Sample code to show how to write a plugin for SSLyze.
#
# Author:       alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
# Licence:      Licensed under the terms of the GPLv2 License
#-------------------------------------------------------------------------------
#!/usr/bin/env python

from plugins import PluginBase


# Class name does not matter as long as it implements PluginBase
class PluginEmpty(PluginBase.PluginBase):

    # available_commands tells the main() what command line options your plugin
    # implements. It's an instance of PluginBase.AvailableCommands.
    # See Python's optparse.OptionGroup documentation to see how it works.
    available_commands = PluginBase.AvailableCommands(
        title='PluginEmpty',
        description=(
            "PluginEmpty is a sample plugin that does not implement"
            "any actual tests. It's designed to show how plugins are written."))
    available_commands.add_option(command="empty", help="Do nothing", dest=None)


    def process_task(self, target, command, args):

        (host, ip_addr, port) = target
        result = []
        result.append('Nothing was done on ' + host + ':' + str(port) +
            "with args: " + args + '...')
        return result
