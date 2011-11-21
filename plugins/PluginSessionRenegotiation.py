#-------------------------------------------------------------------------------
# Name:         PluginSessionRenegotiation.py
# Purpose:      Tests the target server for insecure renegotiation.
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
from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, SSL, SSL_CTX, \
    constants, errors
from utils.CtSSLHelper import FailedSSLHandshake, do_ssl_handshake, \
    load_shared_settings


class PluginSessionRenegotiation(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginSessionRenegotiation",
        description="Tests the target server for insecure renegotiation.")
    available_commands.add_option(
        command="reneg",
        help=(
            "Tests the target server's support for client-initiated "
            'renegotiations and secure renegotiations.'),
        dest=None)


    def process_task(self, target, command, args):

        ctSSL_initialize()
        formatted_results = ['  * {0} : '.format('Session Renegotiation')]
        
        (result_reneg, result_secure) = \
            _test_renegotiation(target, self._shared_settings)
            
        formatted_results.append('      {0:<35} {1}'.format(
            'Client-initiated Renegotiations:',
            result_reneg))
        
        formatted_results.append('      {0:<35} {1}'.format(
            'Secure Renegotiation: ',
            result_secure))
  
        ctSSL_cleanup()
        return formatted_results


def _test_renegotiation(target, shared_settings):
    """
    Checks whether the server honors session renegotation requests and whether
    it supports secure renegotiation.
    """
    (host, ip_addr, port) = target
    result_reneg = 'N/A'
    result_secure = 'N/A'
    ctx = SSL_CTX.SSL_CTX()
    ctx.set_verify(constants.SSL_VERIFY_NONE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl = SSL.SSL(ctx, sock)
    load_shared_settings(ctx, sock, shared_settings) # client cert, etc...

    sock.connect((ip_addr, port))

    try:
        do_ssl_handshake(ssl)

    except FailedSSLHandshake as e:
        raise FailedSSLHandshake('SSL Handshake Failed')

    else:
        result_secure = 'Supported' if ssl.get_secure_renegotiation_support() \
                                    else 'Not Supported'

        try: # Let's try to renegotiate
            ssl.renegotiate()
            result_reneg = 'Honored'

        except errors.ctSSLUnexpectedEOF as e:
            result_reneg = 'Rejected'

        except socket.error as e:
            if 'connection was forcibly closed' in str(e.args):
                result_reneg = 'Rejected'
            elif 'reset by peer' in str(e.args):
                result_reneg = 'Rejected'
            else:
                raise e

        except socket.timeout as e:
            result_reneg = 'Rejected (timeout)'

        except errors.SSLError as e:
            if 'handshake failure' in str(e.args):
                result_reneg = 'Rejected'
            elif 'no renegotiation' in str(e.args):
                result_reneg = 'Rejected'
            else:
                raise e

    finally:
        ssl.shutdown()
        sock.close()

    return (result_reneg, result_secure)