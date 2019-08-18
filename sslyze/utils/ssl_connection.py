import random
import socket
from abc import ABC, abstractmethod
from base64 import b64encode
from typing import Optional

from urllib.parse import quote

from sslyze.server_setting import ServerNetworkLocation, ServerNetworkLocationThroughDirectConnection, \
    ServerNetworkLocationThroughProxy
from sslyze.utils.http_response_parser import HttpResponseParser

import time

from nassl import _nassl
from nassl.ssl_client import SslClient
from nassl.ssl_client import ClientCertificateRequested

from sslyze.utils.tls_wrapped_protocol_helpers import TlsWrappedProtocolHelper


class _ConnectionHelper(ABC):
    """Encapsulate how to open a network socket to the server.
    """

    @abstractmethod
    def __init__(self, server_location: ServerNetworkLocation) -> None:
        pass

    @abstractmethod
    def create_connection(self, timeout: int) -> socket.SocketType:
        pass


class _DirectConnectionHelper(_ConnectionHelper):
    """Open a socket to a server by directly connecting to it.
    """

    def __init__(self, server_location: ServerNetworkLocationThroughDirectConnection) -> None:
        super().__init__(server_location)
        self._server_ip_addr = server_location.ip_address
        self._server_port = server_location.port

    def create_connection(self, timeout: int) -> socket.SocketType:
        sock = socket.create_connection((self._server_ip_addr, self._server_port), timeout=timeout)
        return sock


class ProxyError(IOError):
    """The proxy was offline or did not return HTTP 200 to our CONNECT request.
    """

    pass


class _ProxyTunnelingConnectionHelper(_ConnectionHelper):
    """Open a socket to a server by going through a CONNECT proxy.
    """

    HTTP_CONNECT_REQ = "CONNECT {0}:{1} HTTP/1.1\r\n\r\n"
    HTTP_CONNECT_REQ_PROXY_AUTH_BASIC = "CONNECT {0}:{1} HTTP/1.1\r\nProxy-Authorization: Basic {2}\r\n\r\n"

    ERR_CONNECT_REJECTED = "The proxy rejected the CONNECT request for this host"
    ERR_PROXY_OFFLINE = 'Could not connect to the proxy: "{0}"'

    def __init__(self, server_location: ServerNetworkLocationThroughProxy) -> None:
        super().__init__(server_location)
        # The server we want to connect to via the proxy
        self._server_host = server_location.hostname
        self._server_port = server_location.port

        # The proxy's info
        self._tunnel_host = server_location.http_proxy_settings.hostname
        self._tunnel_port = server_location.http_proxy_settings.port

        self._tunnel_basic_auth_token: Optional[bytes] = None
        basic_auth_user = server_location.http_proxy_settings.basic_auth_user
        basic_auth_password = server_location.http_proxy_settings.basic_auth_password
        if basic_auth_user is not None and basic_auth_password is not None:
            self._tunnel_basic_auth_token = b64encode(
                f"{quote(basic_auth_user)}:{quote(basic_auth_password)}".encode("utf-8")
            )

    def create_connection(self, timeout: int) -> socket.SocketType:
        """Setup HTTP tunneling with the configured proxy.
        """
        # Setup HTTP tunneling
        try:
            sock = socket.create_connection((self._tunnel_host, self._tunnel_port), timeout=timeout)
        except socket.timeout as e:
            raise ProxyError(self.ERR_PROXY_OFFLINE.format(str(e)))
        except socket.error as e:
            raise ProxyError(self.ERR_PROXY_OFFLINE.format(str(e)))

        # Send a CONNECT request with the host we want to tunnel to
        if self._tunnel_basic_auth_token is None:
            sock.send(self.HTTP_CONNECT_REQ.format(self._server_host, self._server_port).encode("utf-8"))
        else:
            sock.send(
                self.HTTP_CONNECT_REQ_PROXY_AUTH_BASIC.format(
                    self._server_host, self._server_port, self._tunnel_basic_auth_token
                ).encode("utf-8")
            )
        http_response = HttpResponseParser.parse_from_socket(sock)

        # Check if the proxy was able to connect to the host
        if http_response.status != 200:
            raise ProxyError(self.ERR_CONNECT_REJECTED)

        return sock


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
        "Nassl SSL handshake failed": "Unexpected EOF",
        "was forcibly closed": "Received FIN",
        "reset by peer": "Received RST",
    }

    HANDSHAKE_REJECTED_SSL_ERRORS = {
        "excessive message size": "Excessive message size",
        "bad mac decode": "Bad mac decode",
        "wrong version number": "Wrong version number",
        "no cipher match": "No cipher match",
        "bad decompression": "Bad decompression",
        "peer error no cipher": "Peer error no cipher",
        "no cipher list": "No ciphers list",
        "insufficient security": "Insufficient security",
        "block type is not 01": "block type is not 01",  # Actually an RSA error
        "wrong ssl version": "Wrong SSL version",
        "sslv3 alert handshake failure": "Alert: handshake failure",
        "tlsv1 alert protocol version": "Alert: protocol version ",
        "tlsv1 alert decrypt error": "Alert: Decrypt error",
        "tlsv1 alert decode error": "Alert: Decode error",
        # The following issues have nothing to do with the server or the connection
        # They are client-side (SSLyze) issues
        # This one is returned by OpenSSL when a cipher set via set_cipher_list() is not
        # actually supported
        "no ciphers available": "No ciphers available",
        # This one is when OpenSSL rejects DH parameters (to protect against Logjam)
        "dh key too small": "DH Key too small",
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
        self, server_location: ServerNetworkLocation, start_tls_helper: TlsWrappedProtocolHelper, ssl_client: SslClient
    ) -> None:
        connection_helper: _ConnectionHelper
        if isinstance(server_location, ServerNetworkLocationThroughProxy):
            connection_helper = _ProxyTunnelingConnectionHelper(server_location)
        elif isinstance(server_location, ServerNetworkLocationThroughDirectConnection):
            connection_helper = _DirectConnectionHelper(server_location)
        else:
            raise ValueError()

        self._connection_helper = connection_helper
        self._start_tls_helper = start_tls_helper
        self.ssl_client = ssl_client

    def do_pre_handshake(self, network_timeout: Optional[int]) -> None:
        # Open a socket to the server
        final_timeout = self.NETWORK_TIMEOUT if network_timeout is None else network_timeout
        sock = self._connection_helper.create_connection(final_timeout)
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
                    raise SslHandshakeRejected("TCP / " + self.HANDSHAKE_REJECTED_SOCKET_ERRORS[error_msg])

            # Unknown socket error
            raise
        except _nassl.OpenSSLError as e:
            for error_msg in self.HANDSHAKE_REJECTED_SSL_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SslHandshakeRejected("TLS / " + self.HANDSHAKE_REJECTED_SSL_ERRORS[error_msg])
            raise  # Unknown SSL error if we get there

    def close(self) -> None:
        self.ssl_client.shutdown()

        # TODO(AD): Remove this after updating nassl
        sock = self.ssl_client.get_underlying_socket()
        if sock:
            sock.close()

    def send_sample_request(self) -> str:
        return self._start_tls_helper.send_sample_request(self.ssl_client)
