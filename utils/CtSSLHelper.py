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
#!/usr/bin/env python

import socket
from ctSSL import errors, constants


class FailedSSLHandshake(Exception):
    pass


def load_shared_settings(ctx, sock, shared_settings):
    """
    Read the shared_settings object shared between all the plugins and load
    the proper settings the ssl context and socket.
    """

    # Load client certificate and private key
    if shared_settings['cert']:
        if shared_settings['certform'] is 'DER':
            ctx.use_certificate_file(
                shared_settings['cert'],
                constants.SSL_FILETYPE_ASN1)
        else:
            ctx.use_certificate_file(
                shared_settings['cert'],
                constants.SSL_FILETYPE_PEM)

        if shared_settings['keyform'] is 'DER':
            ctx.use_PrivateKey_file(
                shared_settings['key'],
                constants.SSL_FILETYPE_ASN1)
        else:
            ctx.use_PrivateKey_file(
                shared_settings['key'],
                constants.SSL_FILETYPE_PEM)

        ctx.check_private_key()

    # Set socket timeout
    sock.settimeout(shared_settings['timeout'])

    # TODO: CONNECT proxy



def load_client_certificate(ctx, shared_settings):
    """
    Loads the client certificate from the shared state object, to the SSL_CTX.
    """

    return


def do_ssl_handshake(ssl):
    """
    Tries to perform a SSL handshake, and raise FailedSSLHandshake if it failed.
    """

    try:
        ssl.do_client_handshake()

    except socket.timeout as e:
            raise FailedSSLHandshake('Failed - Timeout')

    except socket.error as e:
        if 'connection was forcibly closed' in str(e.args):
            raise FailedSSLHandshake('Rejected - TCP FIN')
        elif 'reset by peer' in str(e.args):
            raise FailedSSLHandshake('Rejected - TCP RST')

    except errors.ctSSLUnexpectedEOF as e: # Unexpected EOF
        raise FailedSSLHandshake('Rejected - TCP FIN')

    except errors.SSLErrorSSL as e:
        if 'handshake failure' in str(e.args):
            result_ssl_handshake = 'Rejected - SSL Alert'
        elif "block type is not 01" in str(e.args):
            result_ssl_handshake = 'Failed - SSL Bad block type'
        elif "excessive message size" in str(e.args):
            result_ssl_handshake = 'Failed - SSL Bad message size'
        elif "bad mac decode" in str(e.args):
            result_ssl_handshake = 'Failed - SSL Bad MAC decode'
        elif "wrong version number" in str(e.args):
            result_ssl_handshake = 'Failed - SSL Wrong version'
        elif "no cipher match" in str(e.args):
            result_ssl_handshake = 'Failed - SSL No cipher match'
        elif "no cipher list" in str(e.args):
            result_ssl_handshake = 'Failed - SSL No cipher list'
        elif "no ciphers available" in str(e.args):
            result_ssl_handshake = 'Failed - SSL No ciphers avail'
        elif "bad decompression" in str(e.args):
            result_ssl_handshake = 'Failed - SSL Bad decompression'
        elif "client cert" in str(e.args):
            result_ssl_handshake = 'Error - Client cert needed'
        elif "peer error no cipher" in str(e.args):
            result_ssl_handshake = 'Failed - SSL Peer error no ciph'
        elif "illegal padding" in str(e.args):
            result_ssl_handshake = 'Failed - SSL Illegal padding'
        elif "ecc cert should have sha1 signature" in str(e.args):
            result_ssl_handshake = 'ECC cert should have SHA1 sig'
        elif "insufficient security" in str(e.args):
            result_ssl_handshake = 'Rejected - TLS Insufficient sec'
        else:
            raise e

        raise FailedSSLHandshake(result_ssl_handshake)

    except errors.SSLErrorZeroReturn as e: # Connection abruptly closed by peer
        raise FailedSSLHandshake('Rejected - TCP RST')


def get_http_server_response(ssl, host):
    """
    Recovers the server's response to an HTTP GET.
    Returns the HTTP Response Status Code if there is one.
    """
    # Some websites require the User-Agent header
    # Some websites require Accept: header
    http_get = 'GET / HTTP/1.0\r\n'
    http_get += 'Host: ' + host + '\r\n'
    http_get += 'User-Agent: Mozilla/5.0\r\n'
    http_get += 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n'
    #http_get +='Keep-Alive: 115\r\n'
    http_get +='Connection: close\r\n'
    http_get += '\r\n'

    ssl.write(http_get)
    server_response = ssl.read(4096)

    if len(server_response):
        # Extracting HTTP status from the response
        response_split = (server_response.split('\n', 3))[0].split(None, 1)
        if 'HTTP' not in response_split[0]:
            # Server is not answering to HTTP GET correctly...
            result_http_get = 'Non-HTTP response'
        else:
            result_http_get = response_split[1].strip()
    else:
        # Server answered nothing to HTTP GET...
        result_http_get = 'Non-HTTP response'

    return result_http_get