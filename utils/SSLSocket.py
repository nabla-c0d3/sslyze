#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         SSLSocket.py
# Purpose:      This class mirrors the SSLSocket class from Python's ssl module, 
#               but relies on ctSSL instead.
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
from socket import _fileobject, _delegate_methods, error as socket_error
import errno


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
