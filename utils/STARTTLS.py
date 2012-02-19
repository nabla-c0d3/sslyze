#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         STARTTLS.py
# Purpose:      ctSSL-based STARTTLS support for SMTP.
#
# Author:       alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import socket
from ctSSL import SSL, SSL_CTX
from ctSSL import constants

from SSLSocket import SSLSocket
from CtSSLHelper import filter_handshake_exceptions

class SMTPConnection():
    
    default_port = 25
    
    def __init__(self, host, port=default_port, ssl=None, ssl_ctx=None, 
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        
        self.ssl_ctx = ssl_ctx
        self.ssl = ssl
        self.host = host
        self.port = port
        self.timeout = timeout
        
        if self.ssl_ctx is None:
            self.ssl_ctx = SSL_CTX.SSL_CTX()
            # Can't verify certs by default
            self.ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
    
        if self.ssl is None: 
            self.ssl = SSL.SSL(self.ssl_ctx)
            
    
    def connect(self):
        """
        Connect to a host on a given (SSL) port, send a STARTTLS command,
        and perform the SSL handshake.
        """
        
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout)
        
        # Get the SMTP banner
        smtp_resp = sock.recv(2048)
        
        # Send a EHLO and wait for the 250 status
        sock.send('EHLO sslyze.scan\r\n')
        while '250 ' not in smtp_resp:
            smtp_resp = sock.recv(2048)
                
        # Semd a STARTTLS
        sock.send('STARTTLS\r\n')
        smtp_resp = sock.recv(2048)
        if 'Ready to start TLS'  not in smtp_resp: 
            return

        # Do the SSL handshake
        self.ssl.set_socket(sock)
        ssl_sock = SSLSocket(self.ssl)
        self.sock = ssl_sock
        try:
            ssl_sock.do_handshake()
        except Exception as e:
            filter_handshake_exceptions(e)    
        

    def close(self):
        self.sock.close()