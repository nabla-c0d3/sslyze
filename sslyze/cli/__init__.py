# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.server_connectivity_info import ServerConnectivityInfo
from typing import List


class CompletedServerScan(object):
    """The results of a successful SSLyze scan on a single server.
    """

    def __init__(self, server_info, plugin_result_list):
        # type: (ServerConnectivityInfo, List[PluginScanResult]) -> None
        self.server_info = server_info
        self.plugin_result_list = plugin_result_list
