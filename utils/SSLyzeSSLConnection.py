#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         TODO
# Purpose:      TODO
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
from HTTPResponseParser import parse_http_response
from nassl import SSL_FILETYPE_ASN1,  SSL_FILETYPE_PEM, SSLV23, _nassl
from nassl.SslClient import SslClient



def create_sslyze_connection(shared_settings, sslVersion=SSLV23, sslVerifyLocations=None):
    """
    Utility function to create the proper SSLyzeSSLConnection based on what's 
    in the shared_settings. All plugins should use this.
    """

    # Create the proper SMTP / XMPP / HTTPS connection
    if shared_settings['starttls'] == 'smtp':
        ssl_connection = SSLyzeSMTPConnection(sslVersion, sslVerifyLocations, 
                                        shared_settings['timeout'])
    
    elif shared_settings['starttls'] == 'xmpp':            
        ssl_connection = SSLyzeXMPPConnection(sslVersion, sslVerifyLocations, 
                                        shared_settings['timeout'], 
                                        shared_settings['xmpp_to'])   
             
    elif shared_settings['https_tunnel_host']:
        # TODO
        # Using an HTTP CONNECT proxy to tunnel SSL traffic
        tunnel_host = shared_settings['https_tunnel_host']
        tunnel_port = shared_settings['https_tunnel_port']
        ssl_connection = HTTPSConnection(tunnel_host, tunnel_port, ssl,  
                                        timeout=timeout)
        ssl_connection.set_tunnel(host, port)
    
    elif shared_settings['http_get']:
        ssl_connection = SSLyzeHTTPSConnection(sslVersion, sslVerifyLocations, 
                                               shared_settings['timeout'])    
    else:
        ssl_connection = SSLyzeSSLConnection(sslVersion, sslVerifyLocations, 
                                             shared_settings['timeout'])
    
    
    # Load client certificate and private key
    # These parameters should have been validated when parsing the command line
    if shared_settings['cert']:
        ssl_connection.use_certificate_file(shared_settings['cert'], 
                                            shared_settings['certform'])                
        ssl_connection.use_privateKey_file(shared_settings['key'], 
                                           shared_settings['keyform'], 
                                           shared_settings['keypass'])
        ssl_connection.check_private_key()
    
    
    # Add Server Name Indication
    if shared_settings['sni']:
        ssl_connection.set_tlsext_host_name(shared_settings['sni'])


    return ssl_connection
    


class SSLHandshakeRejected(IOError):
    """
    The server explicitly rejected the SSL handshake.
    """
    pass


class StartTLSError(IOError):
    """
    The server rejected the StartTLS negotiation.
    """
    pass


class ClientAuthenticationError(IOError):
    """
    The server asked for a client certificate and we didn't send one.
    """
    
    ERROR_MSG = 'Server requested a client certificate signed by one of the ' +\
    'following CAs: {0}; use the --cert and --key options.'
    
    def __init__(self, caList):
        self.caList = caList
        
    def __str__(self):
        caListStr = ''
        for ca in self.caList:
            caListStr += ca + ' '
        return self.ERROR_MSG.format(caListStr)



class SSLyzeSSLConnection(SslClient):
    """Base SSL connection class."""

    # The following errors mean that the server explicitly rejected the 
    # handshake. The goal to differentiate rejected handshakes from random 
    # network errors such as the server going offline, etc.
    HANDSHAKE_REJECTED_SOCKET_ERRORS = \
        {'was forcibly closed' : 'Received FIN',
         'reset by peer' : 'Received RST'}
        
    HANDSHAKE_REJECTED_SSL_ERRORS = \
        {'sslv3 alert handshake failure' : 'Alert handshake failure',
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
    
    
    def __init__(self, sslVersion, sslVerifyLocations, timeout):
        super(SSLyzeSSLConnection, self).__init__(None, sslVersion, 
                                                  sslVerifyLocations)
        self.timeout = timeout
    
 
    def do_starttls(self):
        pass
    
    
    def connect(self,(host,port)):
        
        try: # TCP connection            
            self._sock = socket.create_connection((host, port), self.timeout)
        except socket.error as e: 
            # Could not connect to the server although we tested that at startup
            # Did we lose connectivity ?
            raise
                           
                           
        # StartTLS negotiation if there's one
        self.do_starttls()
        
        
        try: # SSL handshake
            self.do_handshake()
            
        # The goal here to differentiate rejected SSL handshakes (which will
        # raise SSLHandshakeRejected) from random network errors
        
        except socket.error as e:
            for error_msg in self.HANDSHAKE_REJECTED_SOCKET_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SSLHandshakeRejected('TCP - ' + self.HANDSHAKE_REJECTED_SOCKET_ERRORS[error_msg])
        
        except IOError as e:
            if 'Nassl SSL handshake failed' in str(e.args):
                raise SSLHandshakeRejected('TLS - Unexpected EOF')
        
        except _nassl.OpenSSLError as e:
            clientCertCaList = self.get_client_CA_list()
            if clientCertCaList: # Server wants a client certificate
                raise ClientAuthenticationError(clientCertCaList)
            
            for error_msg in self.HANDSHAKE_REJECTED_SSL_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SSLHandshakeRejected('TLS - ' + self.HANDSHAKE_REJECTED_SSL_ERRORS[error_msg])
                
            raise # Unknown SSL error if we get there            

        
    def close(self):
        self.shutdown()
        self._sock.close()
        
        
    def post_handshake_check(self):
        return ''
    

class SSLyzeHTTPSConnection(SSLyzeSSLConnection):
    """SSL connection class that sends an HTTP GET request after the SSL
    handshake."""
    
    def post_handshake_check(self):
        
        result = ''
        try: # Send an HTTP GET to the server and store the HTTP Status Code
            self.write('GET / HTTP/1.0\r\nConnection": "close\r\n\r\n')
            # Parse the response and print the Location header
            http_response = parse_http_response(self.read(2048))
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
    

class SSLyzeSMTPConnection(SSLyzeSSLConnection):
    """SSL connection class that performs an SMTP StartTLS negotiation
    before the SSL handshake and sends a NOOP after the handshake."""

    def do_starttls(self):
        # Get the SMTP banner
        self._sock.recv(2048)
        
        # Send a EHLO and wait for the 250 status
        self._sock.send('EHLO sslyze.scan\r\n')
        if '250 ' not in self._sock.recv(2048):
            raise StartTLSError('SMTP EHLO was rejected ?')
                
        # Send a STARTTLS
        self._sock.send('STARTTLS\r\n')
        if 'Ready to start TLS'  not in self._sock.recv(2048): 
            raise StartTLSError('SMTP STARTTLS not supported ?')


    def post_handshake_check(self):
        try:
            self.write('NOOP\r\n')
            result = self.read(2048).strip()
        except socket.timeout:
            result = 'Timeout on SMTP NOOP'
        return result
        
        
class SSLyzeXMPPConnection(SSLyzeSSLConnection):
    """SSL connection class that performs an XMPP StartTLS negotiation
    before the SSL handshake."""
    
    XMPP_OPEN_STREAM = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='{0}'>" 
    XMPP_STARTTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    
    def __init__(self, sslVersion, sslVerifyLocations, timeout, xmpp_to=None):
        super(SSLyzeXMPPConnection, self).__init__(sslVersion, sslVerifyLocations, timeout)
        self._xmpp_to = xmpp_to
        
    
    def connect(self,(host, port)):
        # h4ck
        if self._xmpp_to is None:
            self._xmpp_to = host
    
        return super(SSLyzeXMPPConnection, self).connect((host,port))
    
    
    def do_starttls(self):
        """
        Connect to a host on a given (SSL) port, send a STARTTLS command,
        and perform the SSL handshake.
        """

        # Open an XMPP stream            
        self._sock.send(self.XMPP_OPEN_STREAM.format(self._xmpp_to))
        self._sock.recv(2048)

        # Send a STARTTLS msg
        self._sock.send(self.XMPP_STARTTLS)
        xmpp_resp = self._sock.recv(2048)
        if 'proceed'  not in xmpp_resp: 
            raise StartTLSError('XMPP STARTTLS not supported ?')


