# -*- coding: utf-8 -*-
"""Main abstract plugin classes from which all the plugins should inherit.
"""
from __future__ import absolute_import
from __future__ import unicode_literals

import abc
import inspect
import optparse
from xml.etree.ElementTree import Element

from sslyze.server_connectivity import ServerConnectivityInfo
from typing import List
from typing import Text


class PluginScanCommand(object):
    """Abstract class to represent one specific thing a Plugin can scan for.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self):
        """Optional arguments for a command can be passed as keyword arguments here.
        """
        pass

    @classmethod
    def get_title(cls):
        # type: () -> Text
        """The title of the scan command, to be displayed along with the results.
        """
        raise NotImplementedError()

    @classmethod
    def get_description(cls):
        """The description is expected to be the command class' docstring.
        """
        return cls.__doc__.strip()

    @classmethod
    def get_cli_argument(cls):
        # type: () -> Text
        """Should return the command line option to be used to run the scan command via the CLI.
        """
        raise NotImplementedError()

    @classmethod
    def is_aggressive(cls):
        # type: () -> bool
        """Should return True if command will open many simultaneous connections to the server.

        When using the ConcurrentScanner to run scan commands, only one aggressive command will be run concurrently per
        server, to avoid DOS-ing the server.
        """
        return False

    @classmethod
    def get_optional_arguments(cls):
        # type: () -> List[Text]
        """Some commands support optional arguments which are automatically passed to the command's constructor.
        """
        return inspect.getargspec(cls.__init__).args[1::]


class Plugin(object):
    """Abstract class to represent one plugin which can implement one multiple PluginScanCommand and PluginScanResult.
    """

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
    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, PluginScanCommand) -> PluginScanResult
        """Should run the supplied scan command on the server and return the result.

        Args:
            server_info (ServerConnectivityInfo): The server to run the scan command on.
            scan_command (PluginScanCommand): The scan command.

        Returns:
            PluginScanResult: The result of the scan command run on the supplied server.
        """
        raise NotImplementedError()


class PluginScanResult(object):
    """Abstract class to represent the result of running a specific PluginScanCommand against a server .

    Attributes:
        server_info (ServerConnectivityInfo):  The server against which the command was run.
        scan_command (PluginScanCommand): The scan command that was run against the server.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, PluginScanCommand) -> None
        self.server_info = server_info
        self.scan_command = scan_command

    @abc.abstractmethod
    def as_xml(self):
        # type: () -> Element
        """Should return the XML output to be returned by the CLI tool when --xml_out is used.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def as_text(self):
        # type: () -> List[Text]
        """Should return the text output to be displayed in the console by the CLI tool.
        """
        raise NotImplementedError()

    # Common formatting methods to have a consistent console output
    @staticmethod
    def _format_title(title):
        # type: (Text) -> Text
        return ' * {0}:'.format(title)

    @staticmethod
    def _format_subtitle(subtitle):
        # type: (Text) -> Text
        return '     {0}'.format(subtitle)

    @staticmethod
    def _format_field(title, value):
        # type: (Text, Text) -> Text
        return '       {0:<35}{1}'.format(title, value)
