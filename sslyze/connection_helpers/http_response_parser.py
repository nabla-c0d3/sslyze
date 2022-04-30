from io import BytesIO
from socket import socket
from typing import Callable
from http.client import HTTPResponse
from nassl.ssl_client import BaseSslClient


class _FakeSocket(BytesIO):
    def makefile(self, *args, **kw):  # type: ignore
        return self


class NotAValidHttpResponseError(Exception):
    pass


class HttpResponseParser:
    """Utility to parse HTTP responses - http://pythonwise.blogspot.com/2010/02/parse-http-response.html."""

    @classmethod
    def parse_from_socket(cls, sock: socket) -> HTTPResponse:
        return cls._parse(sock.recv)

    @classmethod
    def parse_from_ssl_connection(cls, ssl_conn: BaseSslClient) -> HTTPResponse:
        return cls._parse(ssl_conn.read)

    @staticmethod
    def _parse(read_method: Callable) -> HTTPResponse:
        """Trick to standardize the API between sockets and SSLConnection objects."""
        response = read_method(4096)
        while b"HTTP/" not in response or b"\r\n\r\n" not in response:
            # Parse until the end of the headers
            response += read_method(4096)

        fake_sock = _FakeSocket(response)
        response = HTTPResponse(fake_sock)  # type: ignore
        response.begin()

        if response.version == 9:
            # HTTP 0.9 => Probably not an HTTP response
            raise NotAValidHttpResponseError()

        return response
