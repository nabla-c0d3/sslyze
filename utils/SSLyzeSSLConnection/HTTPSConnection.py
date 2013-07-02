#!/usr/bin/env python

import socket
from nassl.SslClient import SslClient


class SSLyzeSSLConnection(SslClient):
    

    def __init__(self, sslVersion, sslVerifyLocations, timeout):
        super(SSLyzeSSLConnection, self).__init__(None, sslVersion, 
                                                  sslVerifyLocations)
        self.timeout = timeout
    
    
    def connect(self,(host,port)):
            
        self._sock = socket.create_connection((host, port), self.timeout)                
        self.do_handshake()
        
        
    def close(self):
        self.shutdown()
        self._sock.close()
        
        
    def post_handshake_check(self):
        return ''
    

# TODO: Move this somewhere else
# Utility to parse HTTP responses
from StringIO import StringIO
from httplib import HTTPResponse

class FakeSocket(StringIO):
    def makefile(self, *args, **kw):
        return self

def httpparse(fp):
    socket = FakeSocket(fp)
    response = HTTPResponse(socket)
    response.begin()

    return response


class SSLyzeHTTPSConnection(SSLyzeSSLConnection):
    
    
    def post_handshake_check(self):
        
        result = ''
        try: # Send an HTTP GET to the server and store the HTTP Status Code
            self.write('GET / HTTP/1.0\r\nConnection": "close\r\n\r\n')
            # Parse the response and print the Location header
            http_response = httpparse(self.read(2048))
            if http_response.version == 9 :
                # HTTP 0.9 => Probably not an HTTP response
                result = 'Server response was not HTTP'
            else:    
                result = 'HTTP ' + str(http_response.status) + ' ' \
                       + str(http_response.reason)
                if http_response.status >= 300 and http_response.status < 400:
                    # Add redirection URL to the result
                    redirect = http_response.getheader('Location', None)
                    if redirect:
                        result = result + ' - ' + redirect
                        
        except socket.timeout:
            result = 'Timeout on HTTP GET'
                    
        return result
    
    