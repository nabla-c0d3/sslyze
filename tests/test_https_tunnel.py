# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from tests import SslyzeTestCase

import time

from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin, CertificateInfoScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import HttpConnectTunnelingSettings
from tests.tiny_proxy import ProxyHandler
from tests.tiny_proxy import ThreadingHTTPServer
import multiprocessing


def proxy_worker(hostname, port):
    """Worker method for running an HTTP CONNECT proxy on port 8000.
    """
    server_address = (hostname, port)
    httpd = ThreadingHTTPServer(server_address, ProxyHandler)
    httpd.serve_forever()


class HttpsTunnelTestCase(SslyzeTestCase):


    def test_https_tunneling_bad_arguments(self):
        # Ensure that an IP address cannot be specified when using an HTTP proxy for scans
        tunnel_settings = HttpConnectTunnelingSettings('fakedomain', 443)
        with self.assertRaisesRegexp(ValueError, 'Cannot specify both ip_address and http_tunneling_settings'):
            ServerConnectivityInfo(hostname='www.google.com', ip_address='1.2.3.4',
                                   http_tunneling_settings=tunnel_settings)

    def test_https_tunneling(self):
        # Start a local proxy
        proxy_host = 'localhost'
        proxy_port = 8000
        p = multiprocessing.Process(target=proxy_worker, args=(proxy_host, proxy_port))
        p.start()

        # On Travis CI, the server sometimes is still not ready to accept connections when we get here
        # Wait a bit more to make the test suite less flaky
        time.sleep(0.5)

        try:
            # Run a scan through the proxy
            tunnel_settings = HttpConnectTunnelingSettings(proxy_host, proxy_port, basic_auth_user='test',
                                                           basic_auth_password='test123!')
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
            plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())
            default_certificate = plugin_result.default_certificate

            self.assertGreaterEqual(len(default_certificate.certificate_chain), 1)

            self.assertTrue(plugin_result.as_text())
            self.assertTrue(plugin_result.as_xml())
        finally:
            # Kill the local proxy - unclean
            p.terminate()
