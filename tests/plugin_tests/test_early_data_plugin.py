import pickle

import pytest

from sslyze.plugins.early_data_plugin import EarlyDataPlugin, EarlyDataScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, LegacyOpenSslServer


class TestEarlyDataPlugin:

    @can_only_run_on_linux_64
    def test_early_data_enabled(self):
        with ModernOpenSslServer(max_early_data=256) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            plugin = EarlyDataPlugin()
            plugin_result = plugin.process_task(server_info, EarlyDataScanCommand())

        assert plugin_result.is_early_data_supported

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    @pytest.mark.skip("Find an online server that supports early data; cloudflare disabled support for it")
    def test_early_data_enabled_online(self):
        server_test = ServerConnectivityTester(hostname='www.cloudflare.com')
        server_info = server_test.perform()

        plugin = EarlyDataPlugin()
        plugin_result = plugin.process_task(server_info, EarlyDataScanCommand())

        assert plugin_result.is_early_data_supported

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    @can_only_run_on_linux_64
    def test_early_data_disabled_no_tls_1_3(self):
        with LegacyOpenSslServer() as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            plugin = EarlyDataPlugin()
            plugin_result = plugin.process_task(server_info, EarlyDataScanCommand())

        assert not plugin_result.is_early_data_supported

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    @can_only_run_on_linux_64
    def test_early_data_disabled(self):
        with ModernOpenSslServer(max_early_data=None) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            plugin = EarlyDataPlugin()
            plugin_result = plugin.process_task(server_info, EarlyDataScanCommand())

        assert not plugin_result.is_early_data_supported

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)
