# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import shlex

import subprocess
from platform import architecture
from sys import platform

import logging
import time
from typing import Text

from sslyze.ssl_settings import ClientAuthenticationServerConfigurationEnum


class NotOnLinux64Error(EnvironmentError):
    """The embedded OpenSSL server is only available on Linux 64.
    """


class VulnerableOpenSslServer(object):
    """An OpenSSL server running the 1.0.1e version of OpenSSL, vilnerable to CCS Injection and Heartbleed.
    """

    _OPENSSL_PATH = os.path.join(os.path.dirname(__file__), 'openssl-1-0-0e-linux64')

    _SERVER_CERT_PATH = os.path.join(os.path.dirname(__file__), 'server-self-signed-cert.pem')
    _SERVER_KEY_PATH = os.path.join(os.path.dirname(__file__), 'server-self-signed-key.pem')

    _AVAILABLE_LOCAL_PORTS = set(range(8110, 8150))

    _S_SERVER_CMD = '{openssl} s_server -cert {server_cert} -key {server_key} -accept {port} ' \
                    '-cipher "ALL:COMPLEMENTOFALL" -HTTP'
    _S_SERVER_WITH_OPTIONAL_CLIENT_AUTH_CMD = _S_SERVER_CMD + ' -verify {client_ca}'
    _S_SERVER_WITH_REQUIRED_CLIENT_AUTH_CMD = _S_SERVER_CMD + ' -Verify {client_ca}'

    # Client authentication - files generated using https://gist.github.com/nabla-c0d3/c2c5799a84a4867e5cbae42a5c43f89a
    _CLIENT_CA_PATH = os.path.join(os.path.dirname(__file__), 'client-ca.pem')
    _CLIENT_CERT_PATH = os.path.join(os.path.dirname(__file__), 'client-cert.pem')
    _CLIENT_KEY_PATH = os.path.join(os.path.dirname(__file__), 'client-key.pem')

    @classmethod
    def get_client_certificate_path(cls):
        # type: () -> Text
        return cls._CLIENT_CERT_PATH

    @classmethod
    def get_client_key_path(cls):
        # type: () -> Text
        return cls._CLIENT_KEY_PATH

    @staticmethod
    def is_platform_supported():
        if platform not in ['linux', 'linux2']:
            return False
        if architecture()[0] != '64bit':
            return False
        return True

    def __init__(self, client_auth_config=ClientAuthenticationServerConfigurationEnum.DISABLED):
        # type: (ClientAuthenticationServerConfigurationEnum) -> None
        if not self.is_platform_supported():
            raise NotOnLinux64Error()

        self.hostname = 'localhost'
        self.ip_address = '127.0.0.1'

        # Retrieve one of the available local ports; set.pop() is thread safe
        self.port = self._AVAILABLE_LOCAL_PORTS.pop()
        self._process = None

        if client_auth_config == ClientAuthenticationServerConfigurationEnum.DISABLED:
            self._command_line = self._S_SERVER_CMD.format(
                openssl=self._OPENSSL_PATH,
                server_key=self._SERVER_KEY_PATH,
                server_cert=self._SERVER_CERT_PATH,
                port=self.port,
            )
        elif client_auth_config == ClientAuthenticationServerConfigurationEnum.OPTIONAL:
            self._command_line = self._S_SERVER_WITH_OPTIONAL_CLIENT_AUTH_CMD.format(
                openssl=self._OPENSSL_PATH,
                server_key=self._SERVER_KEY_PATH,
                server_cert=self._SERVER_CERT_PATH,
                port=self.port,
                client_ca=self._CLIENT_CA_PATH,
            )
        elif client_auth_config == ClientAuthenticationServerConfigurationEnum.REQUIRED:
            self._command_line = self._S_SERVER_WITH_REQUIRED_CLIENT_AUTH_CMD.format(
                openssl=self._OPENSSL_PATH,
                server_key=self._SERVER_KEY_PATH,
                server_cert=self._SERVER_CERT_PATH,
                port=self.port,
                client_ca=self._CLIENT_CA_PATH,
            )

    def __enter__(self):
        logging.warning('Running s_server: "{}"'.format(self._command_line))
        args = shlex.split(self._command_line)
        self._process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # Block until s_server is ready to accept requests
        s_server_out = self._process.stdout.readline()
        logging.warning('s_server output: {}'.format(s_server_out))
        while b'ACCEPT' not in s_server_out:
            s_server_out = self._process.stdout.readline()
            logging.warning('s_server output: {}'.format(s_server_out))

        if self._process.poll() is not None:
            # s_server has terminated early - get the error
            s_server_out = self._process.stdout.readline()
            raise RuntimeError('Could not start s_server: {}'.format(s_server_out))

        # On Travis CI, the server sometimes is still not ready to accept connections when we get here
        # Wait a bit more to make the test suite less flaky
        time.sleep(1)

        return self

    def __exit__(self, *args):
        if self._process and self._process.poll() is None:
            self._process.stdout.close()
            self._process.terminate()
            self._process.wait()
        self._process = None

        # Free the port that was used; not thread safe but should be fine
        self._AVAILABLE_LOCAL_PORTS.add(self.port)
        return False
