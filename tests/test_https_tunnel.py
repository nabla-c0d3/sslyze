# -*- coding: utf-8 -*-
import unittest

from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import HttpConnectTunnelingSettings
from tiny_proxy import ProxyHandler
from tiny_proxy import ThreadingHTTPServer
import multiprocessing


class HttpsTunnelTestCase(unittest.TestCase):


    def test_https_tunneling_bad_arguments(self):
        # Ensure that an IP address cannot be specified when using an HTTP proxy for scans
        tunnel_settings = HttpConnectTunnelingSettings('fakedomain', 443)
        with self.assertRaisesRegexp(ValueError, 'Cannot specify both ip_address and http_tunneling_settings'):
            ServerConnectivityInfo(hostname='www.google.com', ip_address='1.2.3.4',
                                   http_tunneling_settings=tunnel_settings)


    @staticmethod
    def _proxy_worker(port):
        """Worker method for running an HTTP CONNECT proxy on port 8000.
        """
        server_address = ('', port)
        httpd = ThreadingHTTPServer(server_address, ProxyHandler)
        httpd.serve_forever()


    def test_https_tunneling(self):
        # Start a local proxy
        proxy_port = 8000
        p = multiprocessing.Process(target=self._proxy_worker, args=(proxy_port, ))
        p.start()

        try:
            # Run a scan through the proxy
            tunnel_settings = HttpConnectTunnelingSettings('localhost', proxy_port)
            server_info = ServerConnectivityInfo(hostname='www.google.com', http_tunneling_settings=tunnel_settings)

            # Try to connect to the proxy - retry if the proxy subprocess wasn't ready
            proxy_connection_attempts = 0
            while True:
                try:
                    server_info.test_connectivity_to_server()
                    break
                except ServerConnectivityError:
                    if proxy_connection_attempts > 3:
                        raise
                    proxy_connection_attempts += 1


            plugin = CertificateInfoPlugin()
            plugin_result = plugin.process_task(server_info, 'certinfo_basic')

            self.assertTrue(plugin_result.certificate_chain)

            self.assertTrue(plugin_result.as_text())
            self.assertTrue(plugin_result.as_xml())
        finally:
            # Kill the local proxy - unclean
            p.terminate()
