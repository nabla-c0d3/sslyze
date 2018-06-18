import socket
from abc import ABC, abstractmethod
from base64 import b64encode
from typing import Optional

from urllib.parse import quote
from sslyze.ssl_settings import HttpConnectTunnelingSettings
from sslyze.utils.http_response_parser import HttpResponseParser


class ProxyError(IOError):
    """The proxy was offline or did not return HTTP 200 to our CONNECT request.
    """
    pass


class ConnectionHelper(ABC):
    """Encapsulate how to open a network socket to the server.
    """

    @abstractmethod
    def connect_socket(self, sock: socket.socket) -> None:
        pass


class DirectConnectionHelper(ConnectionHelper):
    """Open a socket to a server by directly connecting to it.
    """

    def __init__(self, server_ip_addr: str, server_port: int) -> None:
        self._server_ip_addr = server_ip_addr
        self._server_port = server_port

    def connect_socket(self, sock: socket.socket) -> None:
        sock.connect((self._server_ip_addr, self._server_port))


class ProxyTunnelingConnectionHelper(ConnectionHelper):
    """Open a socket to a server by going through a CONNECT proxy.
    """

    HTTP_CONNECT_REQ = 'CONNECT {0}:{1} HTTP/1.1\r\n\r\n'
    HTTP_CONNECT_REQ_PROXY_AUTH_BASIC = 'CONNECT {0}:{1} HTTP/1.1\r\nProxy-Authorization: Basic {2}\r\n\r\n'

    ERR_CONNECT_REJECTED = 'The proxy rejected the CONNECT request for this host'
    ERR_PROXY_OFFLINE = 'Could not connect to the proxy: "{0}"'

    def __init__(self, server_host: str, server_port: int, tunnel_settings: HttpConnectTunnelingSettings) -> None:
        # The server we want to connect to via the proxy
        self._server_host = server_host
        self._server_port = server_port

        # The proxy's info
        self._tunnel_host = tunnel_settings.hostname
        self._tunnel_port = tunnel_settings.port

        self._tunnel_basic_auth_token: Optional[bytes] = None
        if tunnel_settings.basic_auth_user is not None and tunnel_settings.basic_auth_password is not None:
            self._tunnel_basic_auth_token = b64encode(
                f'{quote(tunnel_settings.basic_auth_user)}:{quote(tunnel_settings.basic_auth_password)}'.encode('utf-8')
            )

    def connect_socket(self, sock: socket.socket) -> None:
        """Setup HTTP tunneling with the configured proxy.
        """
        # Setup HTTP tunneling
        try:
            sock.connect((self._tunnel_host, self._tunnel_port))
        except socket.timeout as e:
            raise ProxyError(self.ERR_PROXY_OFFLINE.format(str(e)))
        except socket.error as e:
            raise ProxyError(self.ERR_PROXY_OFFLINE.format(str(e)))

        # Send a CONNECT request with the host we want to tunnel to
        if self._tunnel_basic_auth_token is None:
            sock.send(self.HTTP_CONNECT_REQ.format(self._server_host, self._server_port).encode('utf-8'))
        else:
            sock.send(self.HTTP_CONNECT_REQ_PROXY_AUTH_BASIC.format(
                self._server_host, self._server_port, self._tunnel_basic_auth_token
            ).encode('utf-8'))
        http_response = HttpResponseParser.parse_from_socket(sock)

        # Check if the proxy was able to connect to the host
        if http_response.status != 200:
            raise ProxyError(self.ERR_CONNECT_REJECTED)
