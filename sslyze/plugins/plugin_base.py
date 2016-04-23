# -*- coding: utf-8 -*-
"""Main abstract plugin classes from which all the plugins should inherit.
"""

import abc
from optparse import make_option
from xml.etree.ElementTree import Element


class PluginInterface(object):
    """This object tells SSLyze what the plugin does: its title, description, and which command line option(s) it
    implements.

    Every plugin should have a class attribute called interface that is an instance of PluginInterface.
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
        """Options are settings specific to one single plugin; they will passed to process_task() in the options_dict.
        """
        # If dest is something, store it, otherwise just use store_true
        action="store_true"
        if dest is not None:
            action="store"

        self._options.append(make_option('--{}'.format(option), action=action, help=help, dest=dest))


    def add_command(self, command, help, aggressive=False):
        """Commands are actions/scans the plugin implements, with PluginXXX.process_task().

        Setting aggressive to True is a warning that the command will open many simultaneous connections to the server
        and should therefore not be run concurrently with other `aggressive` commands against a given server.
        """

        self._commands.append(make_option('--{}'.format(command), action='store_true', help=help))
        self._commands_as_text.append((command, aggressive))

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

    # Common formatting
    PLUGIN_TITLE_FORMAT = '  * {0}:'.format
    FIELD_FORMAT = u'      {0:<35}{1}'.format

    def __init__(self, server_info, plugin_command, plugin_options):

        self.server_info = server_info
        self.plugin_command = plugin_command
        self.plugin_options = plugin_options

    @abc.abstractmethod
    def as_xml(self):
        return

    @abc.abstractmethod
    def as_text(self):
        return


class PluginRaisedExceptionResult(PluginResult):
    """Returned when a plugin threw an exception while doing process_task()."""

    def __init__(self, server_info, plugin_command, plugin_options, exception):
        super(PluginRaisedExceptionResult, self).__init__(server_info, plugin_command, plugin_options)
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = '{} - {}'.format(str(exception.__class__.__name__), str(exception))

    TITLE_TXT_FORMAT = 'Unhandled exception while running --{command}:'.format

    def as_text(self):
        return [self.TITLE_TXT_FORMAT(command=self.plugin_command), self.error_message]

    def as_xml(self):
        return Element(self.plugin_command, exception=self.as_text()[1])


class PluginBase(object):
    """Base plugin abstract class. All plugins have to inherit from it.
    """
    __metaclass__ = abc.ABCMeta

    # To be defined in subclasses
    interface = None

    @classmethod
    def get_interface(plugin_class):
        """Returns the AvailableCommands object for the current plugin.
        """
        return plugin_class.interface

    @abc.abstractmethod
    def process_task(self, server_connectivity_info, command, options_dict=None):
        """Completes the task specified by command on the server.

        Args:
            server_connectivity_info (ServerConnectivityInfo):
            command (str):
            options_dict (dict):
        """
        return
