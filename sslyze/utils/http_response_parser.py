# -*- coding: utf-8 -*-
"""Utility to parse HTTP responses - http://pythonwise.blogspot.com/2010/02/parse-http-response.html.
"""
from __future__ import absolute_import
from __future__ import unicode_literals

from io import BytesIO
from socket import socket
from typing import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sslyze.utils.ssl_connection import SSLConnection

try:
    # Python 3
    # noinspection PyCompatibility
    from http.client import HTTPResponse
except ImportError:
    # Python 2
    # noinspection PyCompatibility
    from httplib import HTTPResponse  # type: ignore


class FakeSocket(BytesIO):
    def makefile(self, *args, **kw):  # type: ignore
        return self


class HttpResponseParser(object):

    @classmethod
    def parse_from_socket(cls, sock):
        # type: (socket) -> HTTPResponse
        return cls._parse(sock.recv)

    @classmethod
    def parse_from_ssl_connection(cls, ssl_conn):
        # type: (SSLConnection) -> HTTPResponse
        return cls._parse(ssl_conn.read)

    @staticmethod
    def _parse(read_method):
        # type: (Callable) -> HTTPResponse
        """Trick to standardize the API between sockets and SSLConnection objects.
        """
        response = read_method(4096)
        while b'HTTP/' not in response or b'\r\n\r\n' not in response:
            # Parse until the end of the headers
            response += read_method(4096)

        fake_sock = FakeSocket(response)
        response = HTTPResponse(fake_sock)
        response.begin()
        return response
