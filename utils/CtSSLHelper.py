#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         ctSSLHelper.py
# Purpose:      ctSSL helper functions.
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
from ctSSL import errors


class SSLHandshakeRejected(Exception):
    """
    Exception raised when the server explicitly rejected the handshake.
    """
    pass



class SSLHandshakeError(Exception):
    """
    Exception raised when the handshake failed but we can't tell whether it's 
    because the server rejected it or because something caused it to fail.
    Could be network congestion, the server going offline etc...
    """
    pass


# TODO: Rename, re design
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
            raise SSLHandshakeRejected('TCP FIN')
        elif 'reset by peer' in str(e.args):
            raise SSLHandshakeRejected('TCP RST')

    except errors.ctSSLUnexpectedEOF as e: # Unexpected EOF
        raise SSLHandshakeRejected('TCP FIN')

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
            raise

        raise SSLHandshakeRejected(result_ssl_handshake)

    except errors.SSLErrorZeroReturn as e: # Connection abruptly closed by peer
        raise SSLHandshakeRejected('Rejected - TCP RST')    
