"""Main abstract plugin classes from which all the plugins should inherit.
"""

from abc import ABC, abstractmethod
from concurrent.futures import Future, ThreadPoolExecutor

from dataclasses import dataclass

from typing import List, Callable, Any, Optional, TYPE_CHECKING, Tuple, ClassVar, Dict, Type, Union, TypeVar, Generic


if TYPE_CHECKING:
    from sslyze.server_connectivity import ServerConnectivityInfo
    from sslyze.json import JsonSerializerFunction  # noqa: F401


class ScanCommandResult(ABC):
    pass


class ScanCommandExtraArguments(ABC):
    pass


class ScanCommandWrongUsageError(Exception):
    """Raised when the configuration or arguments passed to complete a scan command are wrong.
    """

    pass


@dataclass(frozen=True)
class ScanJob:
    """One scan job should encapsulate some kind of server testing that uses at most one network connection.

    This allows sslyze to accurately limit how many concurrent connections it opens to a single server.
    """

    function_to_call: Callable
    function_arguments: Any


_ScanCommandResultTypeVar = TypeVar("_ScanCommandResultTypeVar", bound=ScanCommandResult)
_ScanCommandExtraArgumentsTypeVar = TypeVar(
    "_ScanCommandExtraArgumentsTypeVar", bound=Optional[ScanCommandExtraArguments]
)


class ScanCommandImplementation(Generic[_ScanCommandResultTypeVar, _ScanCommandExtraArgumentsTypeVar]):
    """Describes everything needed to run a specific scan command.
    """

    # Contains all the logic for making the scan command available via the CLI
    cli_connector_cls: ClassVar[Type["ScanCommandCliConnector"]]

    @classmethod
    @abstractmethod
    def scan_jobs_for_scan_command(
        cls, server_info: "ServerConnectivityInfo", extra_arguments: Optional[_ScanCommandExtraArgumentsTypeVar] = None
    ) -> List[ScanJob]:
        """Transform a scan command to run into smaller scan jobs to be run concurrently.

        To ensure reliability of the scans, each job should use at most one network connection to the server that is
        being scanned.
        """
        pass

    @classmethod
    @abstractmethod
    def result_for_completed_scan_jobs(
        cls, server_info: "ServerConnectivityInfo", completed_scan_jobs: List[Future]
    ) -> _ScanCommandResultTypeVar:
        """Transform the completed scan jobs for a given scan command into a result.
        """
        pass

    @classmethod
    def scan_server(
        cls, server_info: "ServerConnectivityInfo", extra_arguments: Optional[_ScanCommandExtraArgumentsTypeVar] = None
    ) -> _ScanCommandResultTypeVar:
        """Utility method to run a scan command directly.

        This is useful for the test suite to run commands without using the Scanner class. It should NOT be used to
        actually run scans as this will be very slow (no multi-threading); use the Scanner class instead.
        """
        thread_pool = ThreadPoolExecutor(max_workers=5)

        all_jobs = cls.scan_jobs_for_scan_command(server_info, extra_arguments)
        all_futures = []
        for job in all_jobs:
            future = thread_pool.submit(job.function_to_call, *job.function_arguments)
            all_futures.append(future)

        result = cls.result_for_completed_scan_jobs(server_info, all_futures)
        return result


@dataclass(frozen=True)
class OptParseCliOption:
    option: str
    help: str
    action: str = "store_true"


class ScanCommandCliConnector(Generic[_ScanCommandResultTypeVar, _ScanCommandExtraArgumentsTypeVar]):
    """Contains all the logic for making a scan command available via the CLI.
    """

    _cli_option: ClassVar[str]
    _cli_description: ClassVar[str]

    @classmethod
    def get_cli_options(cls) -> List[OptParseCliOption]:
        """Return the CLI option(s) relevant to the scan command.
        """
        # Subclasses can add command line options for extra arguments here; by default scan commands don't have
        # extra arguments
        return [OptParseCliOption(option=cls._cli_option, help=cls._cli_description)]

    @classmethod
    def find_cli_options_in_command_line(
        cls, parsed_command_line: Dict[str, Union[None, bool, str]]
    ) -> Tuple[bool, Optional[_ScanCommandExtraArgumentsTypeVar]]:
        """Check a parsed command line to see if the CLI option for the scan command was enabled.
        """
        try:
            option = parsed_command_line[cls._cli_option]
            is_scan_cmd_enabled = True if option else False
        except KeyError:
            is_scan_cmd_enabled = False

        extra_arguments = None
        return is_scan_cmd_enabled, extra_arguments

    @classmethod
    def get_json_serializer_functions(cls) -> List["JsonSerializerFunction"]:
        """To be overridden if the scan command returns objects that require custom logic to be serialized to JSON.

        See certificate_info for an example.
        """
        return []

    @classmethod
    @abstractmethod
    def result_to_console_output(cls, result: _ScanCommandResultTypeVar) -> List[str]:
        """Transform the result of the scan command into lines of text to be printed by the CLI.
        """
        pass

    # Common formatting methods to have a consistent console output
    @staticmethod
    def _format_title(title: str) -> str:
        return " * {0}:".format(title)

    @staticmethod
    def _format_subtitle(subtitle: str) -> str:
        return "     {0}".format(subtitle)

    @staticmethod
    def _format_field(title: str, value: str = "") -> str:
        return "       {0:<35}{1}".format(title, value)
