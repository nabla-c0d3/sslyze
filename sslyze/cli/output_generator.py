from abc import ABC, abstractmethod
from typing import TextIO

from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.errors import ConnectionToServerFailed
from sslyze.scanner import ServerScanResult
from sslyze.server_connectivity import ServerConnectivityInfo


class OutputGenerator(ABC):
    """The abstract class output generator classes should inherit from.

    Each method must be implemented and will be called in the order below, as the SSLyze CLI runs scans.
    """

    def __init__(self, file_to: TextIO) -> None:
        self._file_to = file_to

    def close(self) -> None:
        self._file_to.close()

    @abstractmethod
    def command_line_parsed(self, parsed_command_line: ParsedCommandLine) -> None:
        """The CLI was just started and successfully parsed the command line.
        """

    @abstractmethod
    def server_connectivity_test_failed(self, connectivity_error: ConnectionToServerFailed) -> None:
        """The CLI found a server that it could not connect to; no scans will be performed against this server.
        """

    @abstractmethod
    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        """The CLI found a server that it was able to connect to; scans will be run against this server.
        """

    @abstractmethod
    def scans_started(self) -> None:
        """The CLI has finished testing connectivity with the supplied servers and will now start the scans.
        """

    @abstractmethod
    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        """The CLI has finished scanning one single server.
        """

    @abstractmethod
    def scans_completed(self, total_scan_time: float) -> None:
        """The CLI has finished scanning all the supplied servers and will now exit.
        """
