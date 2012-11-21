#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         __init__.py
# Purpose:      Helper class for SSL connections - very specific to SSLyze. 
#               It takes care of all the things SSLyze plugins rely on when 
#               performing an SSL connection, such as properly configuring 
#               SSL_CTX from looking at the shared_settings object.
#               The goal was to put everything related to SSLyze in one spot
#               and keep the rest of the SSL code generic.
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

from utils.ctSSL import SSL, SSL_CTX, errors, constants
from HTTPSConnection import HTTPSConnection
from StartTLS import SMTPConnection, XMPPConnection


class SSLHandshakeRejected(Exception):
    """
    Exception raised when the server explicitly rejected the handshake.
    """
    pass


class ClientCertificateError(Exception):
    """
    Something didn't work when trying to load the client certificate.
    """
    pass


class SSLyzeSSLConnection:
    """
    Helper class for SSL connections - very specific to SSLyze. 
    It takes care of all the things SSLyze plugins rely on when performing 
    an SSL connection, such as properly configuring SSL_CTX from looking at 
    the shared_settings object.
    """
    
    # There is a really annoying bug that causes specific servers to not
    # reply to a client hello that is bigger than 255 bytes.
    # Until this gets fixed, I have to disable cipher suites in order to
    # make our client hello smaller :(
    # Probably this bug:
    # http://rt.openssl.org/Ticket/Display.html?id=2771&user=guest&pass=guest
    SSL_HELLO_WORKAROUND_CIPHERS = "aRSA:AES:-SRP:-PSK:-NULL"
    
    
    # The following errors mean that the server explicitely rejected the handshake
    HANDSHAKE_REJECTED_SOCKET_ERRORS = \
        {'was forcibly closed' : 'Received FIN',
         'reset by peer' : 'Received RST'}
        
    HANDSHAKE_REJECTED_SSL_ERRORS = \
        {'sslv3 alert handshake failure' : 'Handshake failure',
         'no ciphers available' : 'No ciphers available',
         'excessive message size' : 'Excessive message size',
         'bad mac decode' : 'Bad mac decode',
         'wrong version number' : 'Wrong version number',
         'no cipher match' : 'No cipher match',
         'no ciphers available' : 'No ciphers available',
         'bad decompression' : 'Bad decompression',
         'peer error no cipher' : 'Peer error no cipher',
         'no cipher list' : 'No ciphers list',
         'insufficient security' : 'Insufficient security',
         'block type is not 01' : 'block type is not 01'} # Actually an RSA error
    


    def __init__(self, shared_settings, target, ssl_ctx,hello_workaround=False):
        """
        Read the shared_settings object shared between all the plugins and 
        configure the SSL_CTX and SSL objects accordingly.

        @type shared_settings: dict
        @param shared_settings: Shared settings object.

        @type target: (host, ip_addr, port)
        @param target: Server to connect to.
        
        @type ssl_ctx: ctSSL.SSL_CTX
        @param ssl_ctx: SSL_CTX object for the SSL connection.
        
        @type hello_workaround: bool
        @param hello_workaround: Enable client hello workaround.       
        """
    
        timeout = shared_settings['timeout']
        (host, _, port) = target
        if hello_workaround:
            ssl_ctx.set_cipher_list(self.SSL_HELLO_WORKAROUND_CIPHERS)
        
        
        # Load client certificate and private key in the SSL_CTX object
        if shared_settings['cert']:
            if shared_settings['certform'] is 'DER':
                cert_type = constants.SSL_FILETYPE_ASN1
            else:
                cert_type =  constants.SSL_FILETYPE_PEM
                
            if shared_settings['keyform'] is 'DER':
                key_type = constants.SSL_FILETYPE_ASN1
            else:
                key_type = constants.SSL_FILETYPE_PEM
                
            try:
                ssl_ctx.use_certificate_file(shared_settings['cert'], cert_type)                
                ssl_ctx.use_PrivateKey_file(shared_settings['key'], key_type,
                                            shared_settings['keypass'])
                ssl_ctx.check_private_key()
            except errors.OpenSSLError as e: # TODO: Proper error checking
                # Also this should be done much earlier like after parsing the command line
                if 'bad decrypt' in str(e):
                    raise ClientCertificateError('Invalid private key passphrase ?')
                else:
                    raise

        # Create the SSL object
        ssl = SSL.SSL(ssl_ctx)            
        
        # Create the proper SMTP / XMPP / HTTPS connection
        if shared_settings['starttls'] == 'smtp':
            ssl_connection = SMTPConnection(host, port, ssl, timeout)
        elif shared_settings['starttls'] == 'xmpp':
            if shared_settings['xmpp_to']:
                xmpp_to = shared_settings['xmpp_to']
            else:
                xmpp_to = host
                
            ssl_connection = XMPPConnection(host, port, ssl, timeout, xmpp_to)   
                 
        elif shared_settings['https_tunnel_host']:
            # Using an HTTP CONNECT proxy to tunnel SSL traffic
            tunnel_host = shared_settings['https_tunnel_host']
            tunnel_port = shared_settings['https_tunnel_port']
            ssl_connection = HTTPSConnection(tunnel_host, tunnel_port, ssl,  
                                            timeout=timeout)
            ssl_connection.set_tunnel(host, port)
        else:
            ssl_connection = HTTPSConnection(host, port, ssl, timeout=timeout)
            
        
        # All done
        self._ssl_connection = ssl_connection
        self._ssl_ctx = ssl_ctx
        self._ssl = ssl
        self._shared_settings = shared_settings
            
            
    def connect(self):
        """
        Attempts to connect to the server.
        If the connection fails, it tries to identify why the handshake failed 
        by looking at the socket or OpenSSL error.
        
        @raise SSLHandshakeRejected: The handshake was explicitely rejected
        by the other side.
        """
        try: 
            self._ssl_connection.connect()
        
        except socket.error as e:
            for error_msg in self.HANDSHAKE_REJECTED_SOCKET_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SSLHandshakeRejected('TCP - ' + self.HANDSHAKE_REJECTED_SOCKET_ERRORS[error_msg])
            raise
            
        except errors.ctSSLUnexpectedEOF as e: # Unexpected EOF
            raise SSLHandshakeRejected('TCP - Received FIN')
    
        except errors.SSLErrorSSL as e:    
            for error_msg in self.HANDSHAKE_REJECTED_SSL_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SSLHandshakeRejected('TLS Alert - ' + self.HANDSHAKE_REJECTED_SSL_ERRORS[error_msg])
            raise # Unknown SSL error if we get there
                    
        except errors.SSLErrorZeroReturn as e: # Connection abruptly closed by peer
            raise SSLHandshakeRejected('TCP - Received RST')    


    def close(self):
        self._ssl_connection.close()
        
        
    def post_handshake_check(self):
        """
        Check if the SSL connection is still alive after the handshake.
        Will send an HTTP GET for an HTTPS connection.
        Will send a NOOP for an SMTP connection.
        This is only used by PluginOpenSSLCipherSuites for now.
        """    
        ssl_connection = self._ssl_connection
        shared_settings = self._shared_settings
        result = 'N/A'
        
        if shared_settings['starttls'] == 'smtp':
            try:
                ssl_connection.sock.send('NOOP\r\n')
                result = ssl_connection.sock.read(2048).strip()
            except socket.timeout:
                result = 'Timeout on SMTP NOOP'
                
        elif shared_settings['starttls'] == 'xmpp':
            result = ''
            
        elif shared_settings['http_get']:
            try: # Send an HTTP GET to the server and store the HTTP Status Code
                ssl_connection.request("GET", "/", headers={"Connection": "close"})
                http_response = ssl_connection.getresponse()
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
                
        else:
            result = ''
                    
        return result
