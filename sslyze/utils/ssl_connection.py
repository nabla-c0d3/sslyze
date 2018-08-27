import random
import socket
from typing import Optional

import time

from nassl import _nassl
from nassl.ssl_client import SslClient
from nassl.ssl_client import ClientCertificateRequested

from sslyze.utils.connection_helpers import ConnectionHelper
from sslyze.utils.tls_wrapped_protocol_helpers import TlsWrappedProtocolHelper


class SslHandshakeRejected(IOError):
    """The server explicitly rejected the SSL handshake.
    """
    pass


class SslConnection:
    """SSL connection that handles error processing, including retries when receiving timeouts.

    This it the base class to use to connect to a server in order to scan it.
    """

    # The following errors mean that the server explicitly rejected the handshake. The goal to differentiate rejected
    # handshakes from random network errors such as the server going offline, etc.
    HANDSHAKE_REJECTED_SOCKET_ERRORS = {
        'Nassl SSL handshake failed': 'Unexpected EOF',
        'was forcibly closed': 'Received FIN',
        'reset by peer': 'Received RST'
    }

    HANDSHAKE_REJECTED_SSL_ERRORS = {
        'excessive message size': 'Excessive message size',
        'bad mac decode': 'Bad mac decode',
        'wrong version number': 'Wrong version number',
        'no cipher match': 'No cipher match',
        'bad decompression': 'Bad decompression',
        'peer error no cipher': 'Peer error no cipher',
        'no cipher list': 'No ciphers list',
        'insufficient security': 'Insufficient security',
        'block type is not 01': 'block type is not 01',  # Actually an RSA error
        'wrong ssl version': 'Wrong SSL version',
        'sslv3 alert handshake failure': 'Alert: handshake failure',
        'tlsv1 alert protocol version': 'Alert: protocol version ',
        'tlsv1 alert decrypt error': 'Alert: Decrypt error',
        'tlsv1 alert decode error': 'Alert: Decode error',

        # The following issues have nothing to do with the server or the connection
        # They are client-side (SSLyze) issues

        # This one is returned by OpenSSL when a cipher set via set_cipher_list() is not
        # actually supported
        'no ciphers available': 'No ciphers available',

        # This one is when OpenSSL rejects DH parameters (to protect against Logjam)
        'dh key too small': 'DH Key too small',
    }

    # Default socket settings global to all SSLyze connections; can be overridden
    NETWORK_MAX_RETRIES = 3
    NETWORK_TIMEOUT = 5

    @classmethod
    def set_global_network_settings(cls, network_max_retries: int, network_timeout: int) -> None:
        # Not thread-safe
        cls.NETWORK_MAX_RETRIES = network_max_retries
        cls.NETWORK_TIMEOUT = network_timeout

    def __init__(
            self,
            socket_helper: ConnectionHelper,
            start_tls_helper: TlsWrappedProtocolHelper,
            ssl_client: SslClient,
    ) -> None:
        self._socket_helper = socket_helper
        self._start_tls_helper = start_tls_helper
        self.ssl_client = ssl_client

    def do_pre_handshake(self, network_timeout: Optional[int]) -> None:
        # Open a socket to the server
        sock = socket.socket()
        final_timeout = self.NETWORK_TIMEOUT if network_timeout is None else network_timeout
        sock.settimeout(final_timeout)

        self._socket_helper.connect_socket(sock)
        self._start_tls_helper.prepare_socket_for_tls_handshake(sock)

        # Pass the connected socket to the SSL client
        self.ssl_client.set_underlying_socket(sock)

    def connect(self, network_timeout: Optional[int] = None, network_max_retries: Optional[int] = None) -> None:
        final_max_retries = self.NETWORK_MAX_RETRIES if network_max_retries is None else network_max_retries
        retry_attempts = 0
        delay = 0

        # First try to connect to the server, and do retries if there are timeouts
        while True:
            # Sleep if it's a retry attempt
            time.sleep(delay)
            try:
                self.do_pre_handshake(network_timeout)

            except socket.timeout:
                # Attempt to retry connection if a network error occurred during connection or the handshake
                retry_attempts += 1
                if retry_attempts >= final_max_retries:
                    # Exhausted the number of retry attempts, give up
                    raise
                elif retry_attempts == 1:
                    delay = int(random.random())
                else:
                    # Exponential back off
                    delay = min(6, 2 * delay)  # Cap max delay at 6 seconds

            else:
                # No network error occurred
                break

        # After successfully connecting to the server, perform the TLS handshake
        try:
            self.ssl_client.do_handshake()

        except ClientCertificateRequested:
            # Server expected a client certificate and we didn't provide one
            raise
        except socket.timeout:
            # Network timeout, propagate the error
            raise
        except socket.error as e:
            for error_msg in self.HANDSHAKE_REJECTED_SOCKET_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SslHandshakeRejected('TCP / ' + self.HANDSHAKE_REJECTED_SOCKET_ERRORS[error_msg])

            # Unknown socket error
            raise
        except _nassl.OpenSSLError as e:
            for error_msg in self.HANDSHAKE_REJECTED_SSL_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SslHandshakeRejected('TLS / ' + self.HANDSHAKE_REJECTED_SSL_ERRORS[error_msg])
            raise  # Unknown SSL error if we get there

    def close(self) -> None:
        self.ssl_client.shutdown()

        # TODO(AD): Remove this after updating nassl
        sock = self.ssl_client.get_underlying_socket()
        if sock:
            sock.close()

    # TODO(AD): Rename this method to match send_request() ?
    def post_handshake_check(self) -> str:
        return self._start_tls_helper.send_request(self.ssl_client)
