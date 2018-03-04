# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest
import logging

from sslyze.plugins.certificate_info_plugin import CertificateInfoPlugin, CertificateInfoScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionPlugin, OpenSslCcsInjectionScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv30ScanCommand, OpenSslCipherSuitesPlugin
from sslyze.plugins.session_resumption_plugin import SessionResumptionSupportScanCommand, SessionResumptionPlugin
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationCredentials, ClientAuthenticationServerConfigurationEnum
from tests.openssl_server import VulnerableOpenSslServer, NotOnLinux64Error


class ClientAuthenticationTestCase(unittest.TestCase):

    def test_optional_client_auth(self):
        # Given a server that supports optional client authentication
        try:
            with VulnerableOpenSslServer(
                    client_auth_config=ClientAuthenticationServerConfigurationEnum.OPTIONAL
            ) as server:
                server_test = ServerConnectivityTester(
                    hostname=server.hostname,
                    ip_address=server.ip_address,
                    port=server.port
                )
                server_info = server_test.perform()
        except NotOnLinux64Error:
            logging.warning('WARNING: Not on Linux - skipping test')
            return

        # SSLyze correctly detects that client auth is optional
        self.assertEqual(server_info.client_auth_requirement, ClientAuthenticationServerConfigurationEnum.OPTIONAL)

    def test_required_client_auth(self):
        # Given a server that requires client authentication
        try:
            with VulnerableOpenSslServer(
                    client_auth_config=ClientAuthenticationServerConfigurationEnum.REQUIRED
            ) as server:
                server_test = ServerConnectivityTester(
                    hostname=server.hostname,
                    ip_address=server.ip_address,
                    port=server.port
                )
                server_info = server_test.perform()
        except NotOnLinux64Error:
            logging.warning('WARNING: Not on Linux - skipping test')
            return

        # SSLyze correctly detects that client auth is required
        self.assertEqual(server_info.client_auth_requirement, ClientAuthenticationServerConfigurationEnum.REQUIRED)
