
from abc import ABCMeta, abstractmethod

from sslyze.cli import CompletedServerScan
from sslyze.cli import FailedServerScan
from sslyze.server_connectivity import ServerConnectivityInfo


class OutputGenerator(object):
    __metaclass__ = ABCMeta

    def __init__(self, file_to):
        # type: (file) -> None
        self._file_to = file_to

    def close(self):
        # type: (None) -> None
        self._file_to.close()


    @abstractmethod
    def command_line_parsed(self, available_plugins, args_command_list):
        pass

    @abstractmethod
    def server_connectivity_test_failed(self, failed_scan):
        # type: (FailedServerScan) -> None
        pass

    @abstractmethod
    def server_connectivity_test_succeeded(self, server_connectivity_info):
        # type: (ServerConnectivityInfo) -> None
        pass

    @abstractmethod
    def scans_started(self):
        # type: (None) -> None
        pass

    @abstractmethod
    def server_scan_completed(self, server_scan_result):
        # type: (CompletedServerScan) -> None
        pass

    @abstractmethod
    def scans_completed(self, total_scan_time):
        # type: (float) -> None
        pass
