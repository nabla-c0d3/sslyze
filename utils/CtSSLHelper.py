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

from ctSSL import constants
from HTTPSConnection import HTTPSConnection
    
def create_https_connection(target, shared_settings, ssl=None, ssl_ctx=None):
    """
    Read the shared_settings object shared between all the plugins and load
    the proper settings the ssl context and socket.
    """
    
    timeout = shared_settings['timeout']
    (host, ip_addr, port) = target
    
    if shared_settings['https_tunnel_host']:
        # Using an HTTP CONNECT proxy to tunnel SSL traffic
        tunnel_host = shared_settings['https_tunnel_host']
        tunnel_port = shared_settings['https_tunnel_port']
        https_connect = HTTPSConnection(tunnel_host, tunnel_port, ssl, ssl_ctx, 
                                        timeout=timeout)
        https_connect.set_tunnel(host, port)
    else:
        https_connect = HTTPSConnection(ip_addr, port, ssl, ssl_ctx, 
                                        timeout=timeout)
        
        
    # Load client certificate and private key
    if shared_settings['cert']:
        if shared_settings['certform'] is 'DER':
            https_connect.ssl_ctx.use_certificate_file(
                shared_settings['cert'],
                constants.SSL_FILETYPE_ASN1)
        else:
            https_connect.ssl_ctx.use_certificate_file(
                shared_settings['cert'],
                constants.SSL_FILETYPE_PEM)

        if shared_settings['keyform'] is 'DER':
            https_connect.ssl_ctx.use_PrivateKey_file(
                shared_settings['key'],
                constants.SSL_FILETYPE_ASN1)
        else:
            https_connect.ssl_ctx.use_PrivateKey_file(
                shared_settings['key'],
                constants.SSL_FILETYPE_PEM)

        https_connect.ssl_ctx.check_private_key()
        
    return https_connect
