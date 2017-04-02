# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from abc import ABCMeta, abstractmethod

from sslyze.cli import CompletedServerScan
from sslyze.cli import FailedServerScan
from sslyze.server_connectivity import ServerConnectivityInfo


class OutputGenerator(object):
    """The abstract class output generator classes should inherit from.

    Each method must be implemented and will be called in the order below, as the SSLyze CLI runs scans.
    """
    __metaclass__ = ABCMeta

    def __init__(self, file_to):
        # type: (file) -> None
        self._file_to = file_to

    def close(self):
        # type: (None) -> None
        self._file_to.close()

    @abstractmethod
    def command_line_parsed(self, available_plugins, args_command_list):
        """The CLI was just started and successfully parsed the command line.
        """

    @abstractmethod
    def server_connectivity_test_failed(self, failed_scan):
        # type: (FailedServerScan) -> None
        """The CLI found a server that it could not connect to; no scans will be performed against this server.
        """

    @abstractmethod
    def server_connectivity_test_succeeded(self, server_connectivity_info):
        # type: (ServerConnectivityInfo) -> None
        """The CLI found a server that it was able to connect to; scans will be run against this server.
        """

    @abstractmethod
    def scans_started(self):
        # type: (None) -> None
        """The CLI has finished testing connectivity with the supplied servers and will now start the scans.
        """

    @abstractmethod
    def server_scan_completed(self, server_scan_result):
        # type: (CompletedServerScan) -> None
        """The CLI has finished scanning one single server.
        """

    @abstractmethod
    def scans_completed(self, total_scan_time):
        # type: (float) -> None
        """The CLI has finished scanning all the supplied servers and will now exit.
        """
