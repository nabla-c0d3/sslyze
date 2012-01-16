#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         HTTPSConnection.py
# Purpose:      Similar to httplib.HTTPSConnection but uses ctSSL instead of 
#               the standard ssl module. Should eventually be part of ctSSL.
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
from httplib import HTTPConnection, HTTPS_PORT
from socket import _fileobject, _delegate_methods, error as socket_error
import errno

from ctSSL import SSL, SSL_CTX
from ctSSL import errors, constants


class SSLHandshakeFailed(Exception):
    pass


# Create a ctSSL-based HTTPSConnection
class HTTPSConnection(HTTPConnection):
    """
    This class mirrors httplib.HTTPSConnection but uses ctSSL instead of the 
    standard ssl module.
    For now the way to access low level SSL functions associated with a given 
    HTTPSConnection is too just access the ssl and ssl_ctx attribute of the 
    object.
    """
    
    default_port = HTTPS_PORT
    
    def __init__(self, host, port=None, ssl=None, ssl_ctx=None, 
                 strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        
        HTTPConnection.__init__(self, host, port, strict, timeout)

        self.ssl_ctx = ssl_ctx
        self.ssl = ssl
        
        if self.ssl_ctx is None:
            self.ssl_ctx = SSL_CTX.SSL_CTX()
            # Can't verify certs by default
            self.ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
    
        if self.ssl is None: 
            self.ssl = SSL.SSL(self.ssl_ctx)
            
    
    def connect(self):
        "Connect to a host on a given (SSL) port."
    
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout)
        
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
                
              
        # Doing something similar to ssl.wrap_socket() but with ctSSL
        self.ssl.set_socket(sock)
        ssl_sock = SSLSocket(self.ssl)
        
        try:
            ssl_sock.do_handshake()
        except Exception as e:
            filter_handshake_exceptions(e)
            
        self.sock = ssl_sock
        

def filter_handshake_exceptions(exception):
    """
    Try to identify why the handshake failed by looking at the socket or 
    OpenSSL error.
    TODO: Clean that and formatting shouldn't be done here.
    """

    try:
        raise exception
    
    except socket.timeout as e:
            raise # Timeout doesn't mean handshake was rejected.

    except socket.error as e:
        if 'connection was forcibly closed' in str(e.args):
            raise SSLHandshakeFailed('TCP FIN')
        elif 'reset by peer' in str(e.args):
            raise SSLHandshakeFailed('TCP RST')

    except errors.ctSSLUnexpectedEOF as e: # Unexpected EOF
        raise SSLHandshakeFailed('TCP FIN')

    except errors.SSLErrorSSL as e:
        # Parse the OpenSSL error to make it readable
        #openssl_error_msg = str(e[0])
        #try: # Extract the last part of the error
        #    error_msg = openssl_error_msg.split(':')[4]
        #except IndexError: # Couldn't parse the error message ?
        #    error_msg = openssl_error_msg
        #raise SSLHandshakeFailed(error_msg)
        
        result_ssl_handshake = str(e[0]) 
        
        if 'handshake failure' in str(e.args):
            result_ssl_handshake = 'SSL Alert'
        elif "block type is not 01" in str(e.args):
            result_ssl_handshake = 'SSL Bad block type'
        elif "excessive message size" in str(e.args):
            result_ssl_handshake = 'SSL Bad message size'
        elif "bad mac decode" in str(e.args):
            result_ssl_handshake = 'SSL Bad MAC decode'
        elif "wrong version number" in str(e.args):
            result_ssl_handshake = 'SSL Wrong version'
        elif "no cipher match" in str(e.args):
            result_ssl_handshake = 'SSL No cipher match'
        elif "no cipher list" in str(e.args):
            result_ssl_handshake = 'SSL No cipher list'
        elif "no ciphers available" in str(e.args):
            result_ssl_handshake = 'SSL No ciphers avail'
        elif "bad decompression" in str(e.args):
            result_ssl_handshake = 'SSL Bad decompression'
        elif "client cert" in str(e.args):
            result_ssl_handshake = 'Client cert needed'
        elif "peer error no cipher" in str(e.args):
            result_ssl_handshake = 'SSL Peer error no ciph'
        elif "illegal padding" in str(e.args):
            result_ssl_handshake = 'SSL Illegal padding'
        elif "ecc cert should have sha1 signature" in str(e.args):
            result_ssl_handshake = 'ECC cert should have SHA1 sig'
        elif "insufficient security" in str(e.args):
            result_ssl_handshake = 'TLS Insufficient sec'
        else:
            raise e

        raise SSLHandshakeFailed(result_ssl_handshake)

    except errors.SSLErrorZeroReturn as e: # Connection abruptly closed by peer
        raise SSLHandshakeFailed('Rejected - TCP RST')



class SSLSocket(socket.socket):

    """
    This class mirrors the SSLSocket class from Python's ssl module, but 
    relies on ctSSL instead.
    
    @type ssl: ctSSL.SSL
    @param ssl: SSL object.
    """
        
    def __init__(self, ssl, suppress_ragged_eofs=True):
        
        sock = ssl.get_socket()
        socket.socket.__init__(self, _sock=sock._sock)
        # The initializer for socket overrides the methods send(), recv(), etc.
        # in the instancce, which we don't need -- but we want to provide the
        # methods defined in SSLSocket.
        for attr in _delegate_methods:
            try:
                delattr(self, attr)
            except AttributeError:
                pass
                
        # see if it's connected
        try:
            socket.socket.getpeername(self)
        except socket_error, e:
            if e.errno != errno.ENOTCONN:
                raise
            # no, no connection yet
            self._connected = False
        else:
            # yes, create the SSL object
            self._connected = True           
                
                
        self.ssl = ssl
        self._sock = sock
        self.ssl_ctx = ssl.get_ssl_ctx()
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self._makefile_refs = 0

    def read(self, len=1024):
        """Read up to LEN bytes and return them.
        Return zero-length string on EOF."""

        return self.ssl.read(len)


    def write(self, data):
        """Write DATA to the underlying SSL channel.  Returns
        number of bytes of DATA actually transmitted."""

        return self.ssl.write(data)


    def send(self, data, flags=0):
        if flags != 0:
            raise ValueError(
                "non-zero flags not allowed in calls to send() on %s" %
                self.__class__)
            
        return self.ssl.write(data)
                

    def sendto(self, data, flags_or_addr, addr=None):
        raise ValueError("sendto not allowed on instances of %s" %
                         self.__class__)


    def sendall(self, data, flags=0):
        if flags != 0:
            raise ValueError(
                "non-zero flags not allowed in calls to send() on %s" %
                self.__class__)
        return self.ssl.write(data)


    def recv(self, buflen=1024, flags=0):
        if flags != 0:
            raise ValueError(
                "non-zero flags not allowed in calls to send() on %s" %
                self.__class__)
        return self.ssl.read(buflen)
    

    def recv_into(self, buffer, nbytes=None, flags=0):
        if buffer and (nbytes is None):
            nbytes = len(buffer)
        elif nbytes is None:
            nbytes = 1024

        if flags != 0:
            raise ValueError(
              "non-zero flags not allowed in calls to recv_into() on %s" %
              self.__class__)
            
            tmp_buffer = self.ssl.read(nbytes)
            v = len(tmp_buffer)
            buffer[:v] = tmp_buffer
            return v


    def recvfrom(self, buflen=1024, flags=0):
        raise ValueError("recvfrom not allowed on instances of %s" %
                         self.__class__)


    def recvfrom_into(self, buffer, nbytes=None, flags=0):
        raise ValueError("recvfrom_into not allowed on instances of %s" %
                         self.__class__)


    def accept(self):
        # No server side APIs for now
        raise ValueError("recvfrom_into not allowed on instances of %s" %
                         self.__class__)

     
    def pending(self):
        return self.ssl.pending()


    def shutdown(self, how):
        self.ssl.shutdown()
        

    def close(self):
        if self._makefile_refs < 1:
            self.ssl.shutdown()
            self._sock.close()
        else:
            self._makefile_refs -= 1

    def do_handshake(self):

        """Perform a TLS/SSL handshake."""

        self.ssl.do_client_handshake()
        

    def connect(self, addr):
        """Connects to remote ADDR, and then wraps the connection in
        an SSL channel."""
        self._sock.connect(addr)
        self._connected = True
        self.ssl.do_client_handshake()


    def connect_ex(self, addr):
        """Connects to remote ADDR, and then wraps the connection in
        an SSL channel."""
        self._sock.connect(addr)
        self._connected = True
        self.ssl.do_client_handshake()


    def makefile(self, mode='r', bufsize=-1):

        """Make and return a file-like object that
        works with the SSL connection.  Just use the code
        from the socket module."""

        self._makefile_refs += 1
        # close=True so as to decrement the reference count when done with
        # the file-like object.
        return _fileobject(self, mode, bufsize, close=True)

