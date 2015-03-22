
# Utility to parse HTTP responses
# http://pythonwise.blogspot.com/2010/02/parse-http-response.html
from StringIO import StringIO
from httplib import HTTPResponse

class FakeSocket(StringIO):
    def makefile(self, *args, **kw):
        return self


def parse_http_response(sock):

    try:
        # H4ck to standardize the API between sockets and SSLConnection objects
        # sock is a Python socket
        sock.read = sock.recv
    except AttributeError:
        # sock is an SSLConnection
        pass

    response = sock.read(4096)
    if 'HTTP/' not in response:
        # Try to get the rest of the response
        response += sock.read(4096)

    fake_sock = FakeSocket(response)
    response = HTTPResponse(fake_sock)
    response.begin()

    return response

