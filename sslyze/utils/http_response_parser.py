# -*- coding: utf-8 -*-
"""Utility to parse HTTP responses - http://pythonwise.blogspot.com/2010/02/parse-http-response.html.
"""
from __future__ import absolute_import
from __future__ import unicode_literals

from io import BytesIO
try:
    # Python 3
    # noinspection PyCompatibility
    from http.client import HTTPResponse
except ImportError:
    # Python 2
    # noinspection PyCompatibility
    from httplib import HTTPResponse


class FakeSocket(BytesIO):
    def makefile(self, *args, **kw):
        return self


class HttpResponseParser(object):

    @staticmethod
    def parse(sock):

        try:
            # H4ck to standardize the API between sockets and SSLConnection objects
            response = sock.read(4096)
        except AttributeError:
            response = sock.recv(4096)

        while b'HTTP/' not in response or b'\r\n\r\n' not in response:
            # Parse until the end of the headers
            try:
                response += sock.read(4096)
            except AttributeError:
                response += sock.recv(4096)

        fake_sock = FakeSocket(response)
        response = HTTPResponse(fake_sock)
        response.begin()
        return response

