
from sslyze.plugins.plugin_base import PluginResult
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError


class FailedServerScan(object):
    """A scan on a single server that failed because SSLyze could not connect to it.
    """
    
    def __init__(self, server_string, connection_exception):
        # type: (unicode, ServerConnectivityError) -> None
        self.server_string = server_string

        if not isinstance(connection_exception, ServerConnectivityError):
            # Unexpected bug in SSLyze
            raise connection_exception

        self.error_message = connection_exception.error_msg


class CompletedServerScan(object):
    """The results of a successful SSLyze scan on a single server.
    """
    
    def __init__(self, server_info, plugin_result_list):
        # type: (ServerConnectivityInfo, List[PluginResult]) -> None
        self.server_info = server_info
        self.plugin_result_list = plugin_result_list

