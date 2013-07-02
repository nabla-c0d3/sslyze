#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         StartTLS.py
# Purpose:      Quick and dirty ctSSL-based StartTLS support for SMTP and XMPP.
#
# Author:       alban
#
# Copyright:    2012 SSLyze developers
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

from HTTPSConnection import SSLyzeSSLConnection

# TODO: Move this somewhere else
class SSLHandshakeError(Exception):
    pass



class SMTPConnection(SSLyzeSSLConnection):

    
    def connect(self,(host,port)):
            
        sock = socket.create_connection((host, port), self.timeout)
        self._sock = sock           
    
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
        self.do_handshake()


    def post_handshake_check(self):
        try:
            self.write('NOOP\r\n')
            result = self.read(128).strip()
            print result
        except socket.timeout:
            result = 'Timeout on SMTP NOOP'
        return result
        
        
class XMPPConnection(SSLyzeSSLConnection):
    
    XMPP_OPEN_STREAM = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='{0}'>" 
    XMPP_STARTTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    
    def __init__(self, sslVersion, sslVerifyLocations, timeout, xmpp_to=None):
        super(XMPPConnection, self).__init__(sslVersion, sslVerifyLocations, timeout)
        self.xmpp_to = xmpp_to
            
    
    def connect(self,(host,port)):
        """
        Connect to a host on a given (SSL) port, send a STARTTLS command,
        and perform the SSL handshake.
        """

        sock = socket.create_connection((host, port), self.timeout)
        self._sock = sock           
        
        # Open an XMPP stream
        if self.xmpp_to is None:
            xmpp_to = host
        else:
            xmpp_to = self.xmpp_to 
            
        sock.send(self.XMPP_OPEN_STREAM.format(xmpp_to))
        sock.recv(2048)

        # Send a STARTTLS msg
        sock.send(self.XMPP_STARTTLS)
        xmpp_resp = sock.recv(2048)
        if 'proceed'  not in xmpp_resp: 
            raise SSLHandshakeError('XMPP STARTTLS not supported ?')

        self.do_handshake()
        

        