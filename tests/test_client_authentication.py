# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import ClientAuthenticationServerConfigurationEnum
from tests.openssl_server import VulnerableOpenSslServer


class ClientAuthenticationTestCase(unittest.TestCase):

    @unittest.skipIf(not VulnerableOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_optional_client_auth(self):
        # Given a server that supports optional client authentication
        with VulnerableOpenSslServer(
                client_auth_config=ClientAuthenticationServerConfigurationEnum.OPTIONAL
        ) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

        # SSLyze correctly detects that client auth is optional
        self.assertEqual(server_info.client_auth_requirement, ClientAuthenticationServerConfigurationEnum.OPTIONAL)

    @unittest.skipIf(not VulnerableOpenSslServer.is_platform_supported(), 'Not on Linux 64')
    def test_required_client_auth(self):
        # Given a server that requires client authentication
        with VulnerableOpenSslServer(
                client_auth_config=ClientAuthenticationServerConfigurationEnum.REQUIRED
        ) as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

        # SSLyze correctly detects that client auth is required
        self.assertEqual(server_info.client_auth_requirement, ClientAuthenticationServerConfigurationEnum.REQUIRED)
