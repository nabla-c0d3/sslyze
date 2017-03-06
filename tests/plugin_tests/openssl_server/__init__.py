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

    OPENSSL_CMD_LINE = '{openssl} s_server -quiet -cert {cert} -key {key} -accept 4433'

    _PROCESS = None

    @classmethod
    def start(cls):
        if platform not in ['linux', 'linux2']:
            raise NotOnLinux64Error()

        if architecture()[0] != '64bit':
            raise NotOnLinux64Error()

        if cls._PROCESS:
            raise RuntimeError('OpenSSL server is already running')

        final_cmd_line = cls.OPENSSL_CMD_LINE.format(openssl=cls.OPENSSL_PATH, key=cls.KEY_PATH, cert=cls.CERT_PATH)
        args = shlex.split(final_cmd_line)
        cls._PROCESS = subprocess.Popen(args)


    @classmethod
    def terminate(cls):
        cls._PROCESS.terminate()
        cls._PROCESS = None