"""Main abstract plugin classes from which all the plugins should inherit.
"""

import inspect
import optparse
from abc import ABC, abstractmethod
from concurrent.futures import Future
from xml.etree.ElementTree import Element

from dataclasses import dataclass, field

from typing import List, Type, Callable, Any, Set, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from sslyze.plugins.scan_commands import ScanCommandEnum
    from sslyze.server_connectivity_tester import ServerConnectivityInfo


class ScanCommandResult(ABC):
    pass


class ScanCommandExtraArguments(ABC):
    pass


@dataclass(frozen=True)
class ServerScanRequest:
    server_info: "ServerConnectivityInfo"
    scan_commands: Set["ScanCommandEnum"]
    scan_commands_extra_arguments: Dict["ScanCommandEnum", ScanCommandExtraArguments] = field(default_factory=dict)


@dataclass(frozen=True)
class ServerScanResult:
    scan_commands_results: Dict["ScanCommandEnum", ScanCommandResult]

    # What was passed in the corresponding ServerScanRequest
    server_info: "ServerConnectivityInfo"
    scan_commands: Set["ScanCommandEnum"]
    scan_commands_extra_arguments: Dict["ScanCommandEnum", ScanCommandExtraArguments]


@dataclass(frozen=True)
class ScanJob:
    """TODO: 1 job - 1 connection.
    """
    function_to_call: Callable
    function_arguments: Any


class ScanCommandImplementation(ABC):

    @classmethod
    @abstractmethod
    def scan_jobs_for_scan_command(
        cls,
        server_info: "ServerConnectivityInfo",
        extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        pass

    @classmethod
    @abstractmethod
    def result_for_completed_scan_jobs(
        cls,
        server_info: "ServerConnectivityInfo",
        completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
        pass


class PluginScanCommand(ABC):
    """Abstract class to represent one specific thing a Plugin can scan for.
    """

    def __init__(self) -> None:
        """Optional arguments for a command can be passed as keyword arguments here.
        """
        pass

    @classmethod
    @abstractmethod
    def get_title(cls) -> str:
        """The title of the scan command, to be displayed along with the results.
        """
        raise NotImplementedError()

    @classmethod
    def get_description(cls) -> str:
        """The description is expected to be the command class' docstring.
        """
        if cls.__doc__ is None:
            raise ValueError("No docstring found for {}".format(cls.__name__))
        return cls.__doc__.strip()

    @classmethod
    @abstractmethod
    def get_cli_argument(cls) -> str:
        """Should return the command line option to be used to run the scan command via the CLI.
        """
        raise NotImplementedError()

    @classmethod
    def is_aggressive(cls) -> bool:
        """Should return True if command will open many simultaneous connections to the server.

        When using the ConcurrentScanner to run scan commands, only one aggressive command will be run concurrently per
        server, to avoid DOS-ing the server.
        """
        return False

    @classmethod
    def get_optional_arguments(cls) -> List[str]:
        """Some commands support optional arguments which are automatically passed to the command's constructor.
        """
        return inspect.getfullargspec(cls.__init__).args[1::]


class Plugin(ABC):
    """Abstract class to represent one plugin which can implement one multiple PluginScanCommand and PluginScanResult.
    """

    @classmethod
    def get_title(cls) -> str:
        return cls.__name__

    @classmethod
    def get_description(cls) -> str:
        if cls.__doc__ is None:
            raise ValueError("No docstring found for {}".format(cls.__name__))
        return cls.__doc__.strip()

    @classmethod
    @abstractmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        raise NotImplementedError()

    @classmethod
    def get_cli_option_group(cls) -> List[optparse.Option]:
        # TODO(ad): Refactor this to do more, after switching away from optparse
        options = []
        for scan_command_class in cls.get_available_commands():
            if scan_command_class.__doc__ is None:
                raise ValueError("No docstring found for {}".format(cls.__name__))

            options.append(
                optparse.make_option(
                    "--" + scan_command_class.cli_argument,
                    action="store_true",
                    help=scan_command_class.scan_command_class.__doc__.strip(),
                )
            )
        return options

    @abstractmethod
    def process_task(self, server_info: "ServerConnectivityInfo", scan_command: PluginScanCommand) -> "PluginScanResult":
        """Should run the supplied scan command on the server and return the result.

        Args:
            server_info: The server to run the scan command on.
            scan_command: The scan command.

        Returns:
            The result of the scan command run on the supplied server.
        """
        raise NotImplementedError()


class PluginScanResult(ABC):
    """Abstract class to represent the result of running a specific PluginScanCommand against a server .

    Attributes:
        server_info (ServerConnectivityInfo):  The server against which the command was run.
        scan_command (PluginScanCommand): The scan command that was run against the server.
    """

    def __init__(self, server_info: "ServerConnectivityInfo", scan_command: PluginScanCommand) -> None:
        self.server_info = server_info
        self.scan_command = scan_command

    @abstractmethod
    def as_xml(self) -> Element:
        """Should return the XML output to be returned by the CLI tool when --xml_out is used.
        """
        raise NotImplementedError()

    @abstractmethod
    def as_text(self) -> List[str]:
        """Should return the text output to be displayed in the console by the CLI tool.
        """
        raise NotImplementedError()

    # Common formatting methods to have a consistent console output
    @staticmethod
    def _format_title(title: str) -> str:
        return " * {0}:".format(title)

    @staticmethod
    def _format_subtitle(subtitle: str) -> str:
        return "     {0}".format(subtitle)

    @staticmethod
    def _format_field(title: str, value: str) -> str:
        return "       {0:<35}{1}".format(title, value)
