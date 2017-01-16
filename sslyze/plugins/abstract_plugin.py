import inspect
import optparse
from abc import ABCMeta, abstractproperty

from typing import List


class ScanCommand(object):

    __metaclass__ = ABCMeta

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
        raise NotImplementedError()

    @classmethod
    def get_plugin_class(cls):
        raise NotImplementedError()

    @classmethod
    def get_optional_arguments(cls):
        # type: () -> List[str]
        """Some commands support optional arguments which are automatically passed to the command's constructor.
        """
        return inspect.getargspec(cls.__init__).args[1::]



class Plugin(object):

    __metaclass__ = ABCMeta

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
