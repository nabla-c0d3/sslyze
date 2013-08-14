
# Utility to parse HTTP responses
# http://pythonwise.blogspot.com/2010/02/parse-http-response.html
from StringIO import StringIO
from httplib import HTTPResponse

class FakeSocket(StringIO):
    def makefile(self, *args, **kw):
        return self

def parse_http_response(fp):
    socket = FakeSocket(fp)
    response = HTTPResponse(socket)
    response.begin()

    return response

