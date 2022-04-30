"""Main abstract plugin classes from which all the plugins should inherit.
"""

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor

from dataclasses import dataclass

from typing import (
    List,
    Callable,
    Any,
    Optional,
    TYPE_CHECKING,
    Tuple,
    ClassVar,
    Dict,
    Type,
    Union,
    TypeVar,
    Generic,
    Sequence,
)

if TYPE_CHECKING:
    from sslyze.server_connectivity import ServerConnectivityInfo


class ScanCommandResult(ABC):
    pass


class ScanCommandExtraArgument(ABC):
    pass


class ScanCommandWrongUsageError(Exception):
    """Raised when the configuration or arguments passed to complete a scan command are wrong."""

    pass


@dataclass(frozen=True)
class ScanJob:
    """One scan job should encapsulate some kind of server testing that uses at most one network connection.

    This allows sslyze to accurately limit how many concurrent connections it opens to a single server.
    """

    function_to_call: Callable
    function_arguments: Sequence[Any]


@dataclass(frozen=True)
class ScanJobResult:
    _return_value: Optional[Any]
    _exception: Optional[Exception]

    def get_result(self) -> Any:
        if self._exception:
            raise self._exception
        else:
            return self._return_value


_ScanCommandResultTypeVar = TypeVar("_ScanCommandResultTypeVar", bound=ScanCommandResult)
_ScanCommandExtraArgumentTypeVar = TypeVar("_ScanCommandExtraArgumentTypeVar", bound=Optional[ScanCommandExtraArgument])


class ScanCommandImplementation(Generic[_ScanCommandResultTypeVar, _ScanCommandExtraArgumentTypeVar]):
    """Describes everything needed to run a specific scan command."""

    # Contains all the logic for making the scan command available via the CLI
    cli_connector_cls: ClassVar[Type["ScanCommandCliConnector"]]

    @classmethod
    @abstractmethod
    def scan_jobs_for_scan_command(
        cls, server_info: "ServerConnectivityInfo", extra_arguments: Optional[_ScanCommandExtraArgumentTypeVar] = None
    ) -> List[ScanJob]:
        """Transform a scan command to run into smaller scan jobs to be run concurrently.

        To ensure reliability of the scans, each job should use at most one network connection to the server that is
        being scanned.
        """
        pass

    @classmethod
    @abstractmethod
    def result_for_completed_scan_jobs(
        cls, server_info: "ServerConnectivityInfo", scan_job_results: List[ScanJobResult]
    ) -> _ScanCommandResultTypeVar:
        """Transform the individual scan job results for a given scan command into a scan command result."""
        pass

    @classmethod
    def scan_server(
        cls, server_info: "ServerConnectivityInfo", extra_arguments: Optional[_ScanCommandExtraArgumentTypeVar] = None
    ) -> _ScanCommandResultTypeVar:
        """Utility method to run a scan command directly.

        This is useful for the test suite to run commands without using the Scanner class. It should NOT be used to
        actually run scans as this will be very slow (no multi-threading); use the Scanner class instead.
        """
        thread_pool = ThreadPoolExecutor(max_workers=5)

        all_jobs = cls.scan_jobs_for_scan_command(server_info, extra_arguments)
        all_job_results = []
        for job in all_jobs:
            future = thread_pool.submit(job.function_to_call, *job.function_arguments)
            try:
                job_result = ScanJobResult(_return_value=future.result(), _exception=None)
            except Exception as e:
                job_result = ScanJobResult(_return_value=None, _exception=e)
            all_job_results.append(job_result)

        result = cls.result_for_completed_scan_jobs(server_info, all_job_results)
        return result


@dataclass(frozen=True)
class OptParseCliOption:
    option: str
    help: str
    action: str = "store_true"


class ScanCommandCliConnector(Generic[_ScanCommandResultTypeVar, _ScanCommandExtraArgumentTypeVar]):
    """Contains all the logic for making a scan command available via the CLI."""

    _cli_option: ClassVar[str]
    _cli_description: ClassVar[str]

    @classmethod
    def get_cli_options(cls) -> List[OptParseCliOption]:
        """Return the CLI option(s) relevant to the scan command."""
        # Subclasses can add command line options for extra arguments here; by default scan commands don't have
        # extra arguments
        return [OptParseCliOption(option=cls._cli_option, help=cls._cli_description)]

    @classmethod
    def find_cli_options_in_command_line(
        cls, parsed_command_line: Dict[str, Union[None, bool, str]]
    ) -> Tuple[bool, Optional[_ScanCommandExtraArgumentTypeVar]]:
        """Check a parsed command line to see if the CLI option for the scan command was enabled."""
        try:
            option = parsed_command_line[cls._cli_option]
            is_scan_cmd_enabled = True if option else False
        except KeyError:
            is_scan_cmd_enabled = False

        extra_arguments = None
        return is_scan_cmd_enabled, extra_arguments

    @classmethod
    @abstractmethod
    def result_to_console_output(cls, result: _ScanCommandResultTypeVar) -> List[str]:
        """Transform the result of the scan command into lines of text to be printed by the CLI."""
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
