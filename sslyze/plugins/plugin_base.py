# -*- coding: utf-8 -*-
"""Main abstract plugin classes from which all the plugins should inherit.
"""

import abc
from optparse import make_option
from xml.etree.ElementTree import Element

from sslyze.server_connectivity import ServerConnectivityInfo
from typing import Dict
from typing import List
from typing import Optional


class PluginInterface(object):
    """Class to describe what a plugin does: its title, description, and which scan commands it implements.
    """

    def __init__(self, title, description):
        # type: (str, str) -> None
        """Title and description are sent to optparse.OptionGroup().
        """
        self.title = title
        self.description = description
        self._options = []
        self._commands = []
        self._commands_as_text = []

    def add_option(self, option, help, dest=None):
        # type: (str, str, Optional[str]) -> None
        """Options are settings specific to one single plugin; they will passed to process_task() in the options_dict.
        """
        # If dest is something, store it, otherwise just use store_true
        action="store_true"
        if dest is not None:
            action="store"

        self._options.append(make_option('--{}'.format(option), action=action, help=help, dest=dest))


    def add_command(self, command, help, is_aggressive=False):
        # type: (str, str, Optional[bool]) -> None
        """Commands are actions/scans the plugin implements, with PluginXXX.process_task().

        Setting aggressive to True is a warning that the command will open many simultaneous connections to the server
        and should therefore not be run concurrently with other `aggressive` commands against a given server.
        """

        self._commands.append(make_option('--{}'.format(command), action='store_true', help=help))
        self._commands_as_text.append((command, is_aggressive))

    @staticmethod
    def _make_option(command, help, dest):
        # If dest is something, store it, otherwise just use store_true
        action="store_true"
        if dest is not None:
            action="store"

        return make_option('--' + command, action=action, help=help, dest=dest)


    def get_commands(self):
        return self._commands


    def get_commands_as_text(self):
        return self._commands_as_text


    def get_options(self):
        return self._options


class PluginResult(object):
    """Plugins should return the result of process_task() as a subclass of this.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, server_info, plugin_command, plugin_options):
        # type: (ServerConnectivityInfo, str, Dict) -> None

        self.server_info = server_info
        self.plugin_command = plugin_command
        self.plugin_options = plugin_options

    @abc.abstractmethod
    def as_xml(self):
        # type: () -> Element
        raise NotImplementedError()

    @abc.abstractmethod
    def as_text(self):
        # type: () -> List[unicode]
        raise NotImplementedError()

    # Common formatting methods to have a consistent console output
    @staticmethod
    def _format_title(title):
        # type: (unicode) -> unicode
        return '  * {0}:'.format(title)

    @staticmethod
    def _format_field(title, value):
        # type: (unicode, unicode) -> unicode
        return u'      {0:<35}{1}'.format(title, value)


class PluginRaisedExceptionResult(PluginResult):
    """The result returned when a plugin threw an exception while doing process_task().
    """

    def __init__(self, server_info, plugin_command, plugin_options, exception):
        # type: (ServerConnectivityInfo, str, Dict, Exception) -> None
        super(PluginRaisedExceptionResult, self).__init__(server_info, plugin_command, plugin_options)
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = '{} - {}'.format(str(exception.__class__.__name__), str(exception))

    TITLE_TXT_FORMAT = 'Unhandled exception while running --{command}:'

    def as_text(self):
        # type: () -> List[unicode]
        return [self.TITLE_TXT_FORMAT.format(command=self.plugin_command), self.error_message]

    def as_xml(self):
        # type: () -> Element
        return Element(self.plugin_command, exception=self.as_text()[1])


class PluginBase(object):
    """Base plugin abstract class. All plugins have to inherit from it.
    """
    __metaclass__ = abc.ABCMeta

    # Any subclass (ie. an actual plugin) must store its PluginInterface in the subclass' interface attribute.
    interface = None

    def __init__(self):
        if self.interface is None:
            raise TypeError('Plugin did not set a PluginInterface in its interface attribute')

    @classmethod
    def get_interface(cls):
        # type: () -> PluginInterface
        """Return the PluginInterface object for the current plugin.
        """
        return cls.interface

    @abc.abstractmethod
    def process_task(self, server_connectivity_info, command, options_dict=None):
        # type: (ServerConnectivityInfo, str, Optional[Dict]) -> PluginResult
        """Run the supplied scan command on the server.

        Args:
            server_connectivity_info (ServerConnectivityInfo): The server to run the scan command on.
            command (str): The scan command.
            options_dict (dict): Some plugins accept additional settings that can be supplied here.

        Returns:
            PluginResult: The result of the scan command run on the supplied server.
        """
        raise NotImplementedError()
