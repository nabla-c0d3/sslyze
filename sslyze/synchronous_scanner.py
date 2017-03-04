# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.plugins.plugin_base import PluginScanCommand
from sslyze.plugins.plugins_repository import PluginsRepository
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SSLConnection
from typing import Optional


class SynchronousScanner(object):
    """An object to run SSL scanning commands synchronously against a server.
    """

    # Controls every socket connection done by every plugin
    DEFAULT_NETWORK_RETRIES = 3
    DEFAULT_NETWORK_TIMEOUT = 5  # in seconds

    def __init__(self,
                 network_retries=DEFAULT_NETWORK_RETRIES,
                 network_timeout=DEFAULT_NETWORK_TIMEOUT):
        # type: (Optional[int], Optional[int]) -> None
        """Create a scanner for running scanning commands synchronously.

        Args:
            network_retries (Optional[int]): How many times SSLyze should retry a connection that timed out.
            network_timeout (Optional[int]): The time until an ongoing connection times out.
        """
        self._plugins_repository = PluginsRepository()

        # Set global network settings
        SSLConnection.set_global_network_settings(network_retries, network_timeout)

    def run_scan_command(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, PluginScanCommand) -> PluginScanResult
        """Run a single scan command against a server; will block until the scan command has been completed.

        Args:
            server_info(ServerConnectivityInfo): The server's connectivity information. The
                test_connectivity_to_server() method must have been called first to ensure that the server is online
                and accessible.
            scan_command (PluginScanCommand): The scan command to run against this server.

        Returns:
            PluginScanResult: The result of the scan command, which will be an instance of the scan command's
                corresponding PluginScanResult subclass.
        """
        plugin_class = self._plugins_repository.get_plugin_class_for_command(scan_command)
        plugin = plugin_class()
        return plugin.process_task(server_info, scan_command)
