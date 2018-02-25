# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest
import logging

from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin, CertificateInfoScanCommand
from sslyze.plugins.session_resumption_plugin import SessionResumptionSupportScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo, ClientAuthenticationServerConfigurationEnum
from sslyze.ssl_settings import ClientAuthenticationCredentials
from tests.openssl_server import VulnerableOpenSslServer, NotOnLinux64Error


class ClientAuthenticationTestCase(unittest.TestCase):

    def test_optional_client_auth(self):
        # Given a server that supports optional client authentication
        try:
            with VulnerableOpenSslServer(
                    client_auth_config=ClientAuthenticationServerConfigurationEnum.OPTIONAL
            ) as server:
                server_info = ServerConnectivityInfo(
                    hostname=server.hostname,
                    ip_address=server.ip_address,
                    port=server.port
                )
                server_info.test_connectivity_to_server()
        except NotOnLinux64Error:
            # The test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits
            logging.warning('WARNING: Not on Linux - skipping test_fallback_bad() test')
            return

        # SSLyze correctly detects that client auth is optional
        self.assertEqual(server_info.client_auth_requirement, ClientAuthenticationServerConfigurationEnum.OPTIONAL)

    def test_required_client_auth(self):
        # Given a server that requires client authentication
        try:
            with VulnerableOpenSslServer(
                    client_auth_config=ClientAuthenticationServerConfigurationEnum.REQUIRED
            ) as server:
                server_info = ServerConnectivityInfo(
                    hostname=server.hostname,
                    ip_address=server.ip_address,
                    port=server.port
                )
                server_info.test_connectivity_to_server()
        except NotOnLinux64Error:
            # The test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits
            logging.warning('WARNING: Not on Linux - skipping test_fallback_bad() test')
            return

        # SSLyze correctly detects that client auth is required
        self.assertEqual(server_info.client_auth_requirement, ClientAuthenticationServerConfigurationEnum.REQUIRED)

    def test_plugin_works_when_client_auth_failed(self):
        # Given a server that requires client authentication
        try:
            with VulnerableOpenSslServer(
                    client_auth_config=ClientAuthenticationServerConfigurationEnum.REQUIRED
            ) as server:
                server_info = ServerConnectivityInfo(
                    hostname=server.hostname,
                    ip_address=server.ip_address,
                    port=server.port
                )
                server_info.test_connectivity_to_server()
        except NotOnLinux64Error:
            # The test suite only has the vulnerable OpenSSL version compiled for Linux 64 bits
            logging.warning('WARNING: Not on Linux - skipping test_fallback_bad() test')
            return

        # Specific plugins such as CertificateInfoPlugin do work even when a client cert was not supplied
        plugin = CertificateInfoPlugin()
        plugin_result = plugin.process_task(server_info, CertificateInfoScanCommand())
        self.assertTrue(plugin_result.as_text())
        self.assertTrue(plugin_result.as_xml())

    def test_plugin_works_when_client_auth_succeeded(self):
        # TODO
        return