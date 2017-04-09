# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import shlex

import subprocess
from platform import architecture
from sys import platform


class NotOnLinux64Error(EnvironmentError):
    """The embedded OpenSSL server is only available on Linux 64.
    """


class VulnerableOpenSslServer(object):
    """An OpenSSL server running the 1.0.1e version of OpenSSL, vilnerable to CCS Injection and Heartbleed.
    """

    OPENSSL_PATH = os.path.join(os.path.dirname(__file__), 'openssl-1-0-0e-linux64')
    CERT_PATH = os.path.join(os.path.dirname(__file__), 'self-signed-cert.pem')
    KEY_PATH = os.path.join(os.path.dirname(__file__), 'self-signed-key.pem')

    OPENSSL_CMD_LINE = '{openssl} s_server -cert {cert} -key {key} -accept {port} -cipher "ALL:COMPLEMENTOFALL"'

    def __init__(self, port):
        # type: (int) -> None
        if platform not in ['linux', 'linux2']:
            raise NotOnLinux64Error()

        if architecture()[0] != '64bit':
            raise NotOnLinux64Error()

        self.hostname = 'localhost'
        self.ip_address = '127.0.0.1'
        self.port = port
        self._process = None

    def start(self):
        final_cmd_line = self.OPENSSL_CMD_LINE.format(openssl=self.OPENSSL_PATH, key=self.KEY_PATH, cert=self.CERT_PATH,
                                                      port=self.port)
        args = shlex.split(final_cmd_line)
        self._process = subprocess.Popen(args)

    def terminate(self):
        if self._process and self._process.poll() is None:
            self._process.terminate()
