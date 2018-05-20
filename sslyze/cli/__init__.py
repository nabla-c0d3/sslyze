from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.server_connectivity_info import ServerConnectivityInfo
from typing import List


class CompletedServerScan:
    """The results of a successful SSLyze scan on a single server.
    """

    def __init__(self, server_info: ServerConnectivityInfo, plugin_result_list: List[PluginScanResult]) -> None:
        self.server_info = server_info
        self.plugin_result_list = plugin_result_list
