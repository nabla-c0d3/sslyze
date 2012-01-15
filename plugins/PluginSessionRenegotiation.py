#!/usr/bin/env python
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

import socket
from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, SSL_CTX, \
    constants, errors
from utils.CtSSLHelper import create_https_connection
from utils.HTTPSConnection import SSLHandshakeFailed


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
        try:
            (result_reneg, result_secure) = \
                _test_renegotiation(target, self._shared_settings)
        except:
            raise
        finally:
            ctSSL_cleanup()
            
        formatted_results = ['  * {0} : '.format('Session Renegotiation')]
        formatted_results.append('      {0:<35} {1}'.format(
            'Client-initiated Renegotiations:',
            result_reneg))
        formatted_results.append('      {0:<35} {1}'.format(
            'Secure Renegotiation: ',
            result_secure))
        
        return formatted_results


def _test_renegotiation(target, shared_settings):
    """
    Checks whether the server honors session renegotation requests and whether
    it supports secure renegotiation.
    """
    result_reneg = 'N/A'
    result_secure = 'N/A'
    
    ssl_ctx = SSL_CTX.SSL_CTX()
    ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
    https_connect = \
        create_https_connection(target, shared_settings, ssl_ctx=ssl_ctx)

    try:
        https_connect.connect()
    except SSLHandshakeFailed as e:
        raise SSLHandshakeFailed('SSL Handshake Failed')
    else:
        result_secure = 'Supported' if https_connect.ssl.get_secure_renegotiation_support() \
                                    else 'Not Supported'

        try: # Let's try to renegotiate
            https_connect.ssl.renegotiate()
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
        https_connect.close()

    return (result_reneg, result_secure)