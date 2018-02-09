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


NOT_ON_LINUX_64BIT = platform not in ['linux', 'linux2'] or architecture()[0] != '64bit'


class VulnerableOpenSslServer(object):
    """An OpenSSL server running the 1.0.1e version of OpenSSL, vilnerable to CCS Injection and Heartbleed.
    """

    OPENSSL_PATH = os.path.join(os.path.dirname(__file__), 'openssl-1-0-0e-linux64')
    CERT_PATH = os.path.join(os.path.dirname(__file__), 'self-signed-cert.pem')
    KEY_PATH = os.path.join(os.path.dirname(__file__), 'self-signed-key.pem')

    AVAILABLE_LOCAL_PORTS = set(range(8110, 8150))

    OPENSSL_CMD_LINE = '{openssl} s_server -cert {cert} -key {key} -accept {port} -cipher "ALL:COMPLEMENTOFALL"'

    def __init__(self):
        # type: (int) -> None
        if NOT_ON_LINUX_64BIT:
            EnvironmentError('The embedded OpenSSL server is only available on Linux 64.')

        self.hostname = 'localhost'
        self.ip_address = '127.0.0.1'

        # Retrieve one of the available local ports; set.pop() is thread safe
        self.port = self.AVAILABLE_LOCAL_PORTS.pop()
        self._process = None

    def __enter__(self):
        final_cmd_line = self.OPENSSL_CMD_LINE.format(openssl=self.OPENSSL_PATH, key=self.KEY_PATH, cert=self.CERT_PATH,
                                                      port=self.port)
        args = shlex.split(final_cmd_line)
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
        time.sleep(0.5)

        return self

    def __exit__(self, *args):
        if self._process and self._process.poll() is None:
            self._process.terminate()

        # Free the port that was used; not thread safe but should be fine
        self.AVAILABLE_LOCAL_PORTS.add(self.port)
        return False
