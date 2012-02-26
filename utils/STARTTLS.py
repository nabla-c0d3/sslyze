#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         STARTTLS.py
# Purpose:      Quick and dirty ctSSL-based STARTTLS support for SMTP and XMPP.
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
from CtSSLHelper import filter_handshake_exceptions, SSLHandshakeError

class SMTPConnection():
    
    default_port = 25
    
    def __init__(self, host, port=default_port, ssl=None, ssl_ctx=None, 
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        
        self.ssl_ctx = ssl_ctx
        self.ssl = ssl
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        
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
        self.sock = sock
        

        # Get the SMTP banner
        sock.recv(2048)
        
        # Send a EHLO and wait for the 250 status
        sock.send('EHLO sslyze.scan\r\n')
        smtp_resp = sock.recv(2048)
        if '250 ' not in smtp_resp:
            raise SSLHandshakeError('SMTP EHLO was rejected ?')
                
        # Send a STARTTLS
        sock.send('STARTTLS\r\n')
        smtp_resp = sock.recv(2048)
        if 'Ready to start TLS'  not in smtp_resp: 
            raise SSLHandshakeError('SMTP STARTTLS not supported ?')

        # Do the SSL handshake
        self.ssl.set_socket(sock)
        ssl_sock = SSLSocket(self.ssl)

            
        try:
            ssl_sock.do_handshake()
        except Exception as e:
            filter_handshake_exceptions(e)    
            
        self.sock = ssl_sock
        

    def close(self):
        self.sock.close()
        
        
        
class XMPPConnection():
    
    default_port = 5222
    xmpp_open_stream = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='{0}'>" 
    xmpp_starttls = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    
    def __init__(self, host, port=default_port, ssl=None, ssl_ctx=None, 
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT, xmpp_to=None):
        
        self.ssl_ctx = ssl_ctx
        self.ssl = ssl
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        if xmpp_to is None:
            self.xmpp_to = host
        else:
            self.xmpp_to = xmpp_to
        
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
        self.sock = sock
        
        # Open an XMPP stream
        sock.send(self.xmpp_open_stream.format(self.xmpp_to))
        sock.recv(2048)
                
        # Send a STARTTLS
        sock.send(self.xmpp_starttls)
        xmpp_resp = sock.recv(2048)
        if 'proceed'  not in xmpp_resp: 
            raise SSLHandshakeError('XMPP STARTTLS not supported ?')

        # Do the SSL handshake
        self.ssl.set_socket(sock)
        ssl_sock = SSLSocket(self.ssl)

            
        try:
            ssl_sock.do_handshake()
        except Exception as e:
            filter_handshake_exceptions(e)    
            
        self.sock = ssl_sock
        

    def close(self):
        self.sock.close()
        