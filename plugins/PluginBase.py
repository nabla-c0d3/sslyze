#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginBase.py
# Purpose:      Main abstract plugin class. All the plugins are
#               subclasses of PluginBase.
#
# Author:       aaron, alban
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

import abc
from optparse import make_option

class PluginInterface:
    """
    This object tells SSLyze what the plugin does: its title, description, and
    which command line option(s) it implements.
    Every plugin should have a class attribute called interface that is an
    instance of PluginInterface.
    """

    def __init__(self, title, description):
        """
        Title and description are sent to optparse.OptionGroup().
        """
        self.title = title
        self.description = description
        self._options = []
        self._commands = []
        self._commands_as_text = []

    def add_option(self, option, help, dest=None):
        """
        Options are settings specific to one single plugin.
        They are sent to PluginBase._shared_settings.
        """

        self._options.append(self._make_option(option, help, dest))


    def add_command(self, command, help, dest=None, aggressive=False):
        """
        Commands are actions/scans the plugin implements, with
        PluginXXX.process_task().
        Note: dest to None if you don't need arguments.
        Setting aggressive to True means that the command will open
        many simultaneous connections to the server and should therefore
        not be run concurrently with other `aggressive` commands against
        a given server.
        """

        self._commands.append(self._make_option(command, help, dest))
        self._commands_as_text.append((command, aggressive))


    def get_commands(self):
        return self._commands


    def get_commands_as_text(self):
        return self._commands_as_text


    def get_options(self):
        return self._options


    @staticmethod
    def _make_option(command, help, dest):
        # If dest is something, store it, otherwise just use store_true
        action="store_true"
        if dest is not None:
            action="store"

        return make_option('--' + command, action=action, help=help, dest=dest)


class PluginResult:
    """
    Plugin.process_task() should return an instance of this class.
    """
    def __init__(self, text_result, xml_result):
        """
        @type text_result: [str]
        @param text_result: Printable version of the plugin's results.
        Each string within the list gets printed as a separate line.

        @type xml_result: xml.etree.ElementTree.Element
        @param xml_result: XML version of the plugin's results.
        """
        self._text_result = text_result
        self._xml_result = xml_result

    def get_xml_result(self):
        return self._xml_result

    def get_txt_result(self):
        return self._text_result



class PluginBase(object):
    """
    Base plugin abstract class. All plugins have to inherit from it.
    """
    __metaclass__ = abc.ABCMeta

    # _shared_settings contains read-only info available to all the plugins:
    # client certificate, timeoutvalue, etc...
    # TODO: Document it
    _shared_settings = None

    # Formatting stuff
    PLUGIN_TITLE_FORMAT = '  * {0}:'.format
    FIELD_FORMAT = '      {0:<35}{1}'.format


    @classmethod
    def get_interface(plugin_class):
        """
        This method returns the AvailableCommands object for the current plugin.
        """
        return plugin_class.interface

    @abc.abstractmethod
    def process_task(self, target, command, args):
        """
        This method should implement what the plugin is expected to do / test
        when given a target=(host, ip_addr, port), a command line option, and
        a command line argument. It has to be defined in each plugin class.
        """
        return

