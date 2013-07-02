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
        
        
    def post_handshake_check(self):
        return ''
    


class SSLyzeHTTPSConnection(SSLyzeSSLConnection):
    
    
    def post_handshake_check(self):
        self.write('GET / HTTP/1.0\r\nConnection": "close\r\n\r\n')
        # TODO: Parse the response and print the Location header
        result = self.read(10)           
        return result