#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         SharedSettingsHelper.py
# Purpose:      Helper functions to create the right SSL connection based on 
#               what's in the shared_settings object.
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

from ctSSL import constants
from HTTPSConnection import HTTPSConnection
import STARTTLS
import socket
    
def create_ssl_connection(target, shared_settings, ssl=None, ssl_ctx=None):
    """
    Read the shared_settings object shared between all the plugins and load
    the proper settings the ssl context and socket.
    """
    
    timeout = shared_settings['timeout']
    (host, ip_addr, port) = target
    
    if shared_settings['starttls'] == 'smtp':
        ssl_connection = STARTTLS.SMTPConnection(ip_addr, port, ssl, ssl_ctx, 
                                                 timeout=timeout)
    elif shared_settings['starttls'] == 'xmpp':
        if shared_settings['xmpp_to']:
            xmpp_to = shared_settings['xmpp_to']
        else:
            xmpp_to = host
            
        ssl_connection = \
            STARTTLS.XMPPConnection(ip_addr, port, ssl, ssl_ctx, 
                                    timeout=timeout, xmpp_to=xmpp_to)   
             
    elif shared_settings['https_tunnel_host']:
        # Using an HTTP CONNECT proxy to tunnel SSL traffic
        tunnel_host = shared_settings['https_tunnel_host']
        tunnel_port = shared_settings['https_tunnel_port']
        ssl_connection = HTTPSConnection(tunnel_host, tunnel_port, ssl, ssl_ctx, 
                                        timeout=timeout)
        ssl_connection.set_tunnel(host, port)
    else:
        ssl_connection = HTTPSConnection(ip_addr, port, ssl, ssl_ctx, 
                                        timeout=timeout)
        
        
    # Load client certificate and private key
    if shared_settings['cert']:
        if shared_settings['certform'] is 'DER':
            ssl_connection.ssl_ctx.use_certificate_file(
                shared_settings['cert'],
                constants.SSL_FILETYPE_ASN1)
        else:
            ssl_connection.ssl_ctx.use_certificate_file(
                shared_settings['cert'],
                constants.SSL_FILETYPE_PEM)

        if shared_settings['keyform'] is 'DER':
            ssl_connection.ssl_ctx.use_PrivateKey_file(
                shared_settings['key'],
                constants.SSL_FILETYPE_ASN1)
        else:
            ssl_connection.ssl_ctx.use_PrivateKey_file(
                shared_settings['key'],
                constants.SSL_FILETYPE_PEM)

        ssl_connection.ssl_ctx.check_private_key()
        
    return ssl_connection



def check_ssl_connection_is_alive(ssl_connection, shared_settings):
    """
    Check if the SSL connection is still alive after the handshake.
    Will send an HTTP GET for an HTTPS connection.
    Will send a NOOP for an SMTP connection.
    """    

    result = 'N/A'
    if shared_settings['starttls'] == 'smtp':
        try:
            ssl_connection.sock.send('NOOP\r\n')
            result = ssl_connection.sock.read(2048).strip()
        except socket.timeout:
            result = 'Timeout on SMTP NOOP'
    elif shared_settings['starttls'] == 'xmpp':
        result = 'OK'
    else:
        try: 
            # Send an HTTP GET to the server and store the HTTP Status Code
            ssl_connection.request("GET", "/", headers={"Connection": "close"})
            http_response = ssl_connection.getresponse()
            result = 'HTTP ' \
                + str(http_response.status) \
                + ' ' \
                + str(http_response.reason)
        except socket.timeout:
            result = 'Timeout on HTTP GET'


    return result
    