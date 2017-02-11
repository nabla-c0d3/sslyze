# -*- coding: utf-8 -*-
"""Main abstract plugin classes from which all the plugins should inherit.
"""

import abc
import inspect
import optparse
from xml.etree.ElementTree import Element

from sslyze.server_connectivity import ServerConnectivityInfo
from typing import List


class ScanCommand(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self):
        """Optional arguments for a command can be passed as keyword arguments here.
        """
        pass

    @classmethod
    def get_description(cls):
        """The description is expected to be the command class' docstring.
        """
        return cls.__doc__.strip()

    @classmethod
    def get_cli_argument(cls):
        # type: () -> str
        """Should return the command line option to be used to run the scan command via the CLI.
        """
        raise NotImplementedError()

    @classmethod
    def is_aggressive(cls):
        # type: () -> bool
        """Should return True if command will open many simultaneous connections to the server.

        When using the PluginsProcessPool to run scan commands, only one aggressive command will be run concurrently per
        server, to avoid DOS-ing the server.
        """
        return False

    @classmethod
    def get_optional_arguments(cls):
        # type: () -> List[str]
        """Some commands support optional arguments which are automatically passed to the command's constructor.
        """
        return inspect.getargspec(cls.__init__).args[1::]


class Plugin(object):

    __metaclass__ = abc.ABCMeta

    @classmethod
    def get_title(cls):
        return cls.__name__

    @classmethod
    def get_description(cls):
        return cls.__doc__.strip()

    @classmethod
    def get_available_commands(cls):
        raise NotImplementedError()

    @classmethod
    def get_cli_option_group(cls):
        # TODO(ad): Refactor this to do more, after switching away from optparse
        options = []
        for scan_command_class in cls.get_available_commands():
            options.append(optparse.make_option('--' + scan_command_class.get_cli_argument(), action='store_true',
                                                help=scan_command_class.get_description()))
        return options


    @abc.abstractmethod
    def process_task(self, server_connectivity_info, command):
        # type: (ServerConnectivityInfo, ScanCommand) -> PluginResult
        """Run the supplied scan command on the server.

        Args:
            server_connectivity_info (ServerConnectivityInfo): The server to run the scan command on.
            command (ScanCommand): The scan command.

        Returns:
            PluginResult: The result of the scan command run on the supplied server.
        """
        raise NotImplementedError()


class PluginResult(object):
    """Plugins should return the result of process_task() as a subclass of this.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, ScanCommand) -> None
        self.server_info = server_info
        self.scan_command = scan_command

    @abc.abstractmethod
    def as_xml(self):
        # type: () -> Element
        raise NotImplementedError()

    @abc.abstractmethod
    def as_text(self):
        # type: () -> List[Text]
        raise NotImplementedError()

    # Common formatting methods to have a consistent console output
    @staticmethod
    def _format_title(title):
        # type: (Text) -> Text
        return '  * {0}:'.format(title)

    @staticmethod
    def _format_field(title, value):
        # type: (Text, Text) -> Text
        return u'      {0:<35}{1}'.format(title, value)


class PluginRaisedExceptionResult(PluginResult):
    """The result returned when a plugin threw an exception while doing process_task().
    """

    def __init__(self, server_info, scan_command, exception):
        # type: (ServerConnectivityInfo, ScanCommand, Exception) -> None
        super(PluginRaisedExceptionResult, self).__init__(server_info, scan_command)
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = u'{} - {}'.format(str(exception.__class__.__name__), str(exception))

    TITLE_TXT_FORMAT = u'Unhandled exception while running --{command}:'

    def as_text(self):
        # type: () -> List[Text]
        return [self.TITLE_TXT_FORMAT.format(command=self.scan_command.get_cli_argument()), self.error_message]

    def as_xml(self):
        # type: () -> Element
        return Element(self.scan_command.get_cli_argument(), exception=self.as_text()[1])
