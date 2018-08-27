from io import BytesIO
from socket import socket
from typing import Callable
from http.client import HTTPResponse
from nassl.ssl_client import SslClient


class _FakeSocket(BytesIO):
    def makefile(self, *args, **kw):  # type: ignore
        return self


class HttpResponseParser:
    """Utility to parse HTTP responses - http://pythonwise.blogspot.com/2010/02/parse-http-response.html.
    """

    @classmethod
    def parse_from_socket(cls, sock: socket) -> HTTPResponse:
        return cls._parse(sock.recv)

    @classmethod
    def parse_from_ssl_connection(cls, ssl_conn: SslClient) -> HTTPResponse:
        return cls._parse(ssl_conn.read)

    @staticmethod
    def _parse(read_method: Callable) -> HTTPResponse:
        """Trick to standardize the API between sockets and SSLConnection objects.
        """
        response = read_method(4096)
        while b'HTTP/' not in response or b'\r\n\r\n' not in response:
            # Parse until the end of the headers
            response += read_method(4096)

        fake_sock = _FakeSocket(response)
        response = HTTPResponse(fake_sock)  # type: ignore
        response.begin()
        return response
