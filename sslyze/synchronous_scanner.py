from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.plugins.plugin_base import PluginScanCommand
from sslyze.plugins.plugins_repository import PluginsRepository
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SslConnection


class SynchronousScanner:
    """An object to run SSL scanning commands synchronously against a server.
    """

    # Controls every socket connection done by every plugin
    DEFAULT_NETWORK_RETRIES = 3
    DEFAULT_NETWORK_TIMEOUT = 5  # in seconds

    def __init__(
            self,
            network_retries: int = DEFAULT_NETWORK_RETRIES,
            network_timeout: int = DEFAULT_NETWORK_TIMEOUT
    ) -> None:
        """Create a scanner for running scanning commands synchronously.

        Args:
            network_retries: How many times SSLyze should retry a connection that timed out.
            network_timeout: The time until an ongoing connection times out.
        """
        self._plugins_repository = PluginsRepository()

        # Set global network settings
        SslConnection.set_global_network_settings(network_retries, network_timeout)

    def run_scan_command(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: PluginScanCommand
    ) -> PluginScanResult:
        """Run a single scan command against a server; will block until the scan command has been completed.

        Args:
            server_info: The server's connectivity information. The test_connectivity_to_server() method must have been
                called first to ensure that the server is online and accessible.
            scan_command: The scan command to run against this server.

        Returns:
            The result of the scan command, which will be an instance of the scan command's
            corresponding PluginScanResult subclass.
        """
        plugin_class = self._plugins_repository.get_plugin_class_for_command(scan_command)
        plugin = plugin_class()
        return plugin.process_task(server_info, scan_command)
