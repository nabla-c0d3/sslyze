#-------------------------------------------------------------------------------
# Name:         PluginSessionRenegotiation.py
# Purpose:      Tests the target server for insecure renegotiation.
#
# Author:       alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
# Licence:      Licensed under the terms of the GPLv2 License
#-------------------------------------------------------------------------------
#!/usr/bin/env python

import socket
from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, SSL, SSL_CTX, \
    constants, errors
from utils.CtSSLHelper import FailedSSLHandshake, do_ssl_handshake, \
    get_http_server_response, load_client_certificate


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

        try:  # We need OpenSSL 0.9.8m or later to check for insecure reneg
            ctx = SSL_CTX.SSL_CTX()
            ctx.set_options(constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
        except AttributeError:
            formatted_results.append('OpenSSL version is 0.9.8l or earlier. '
            "Can't test for insecure renegotiation. Update OpenSSL to 0.9.8m+.")
        else:
            try: # OpenSSL version is OK, test insecure reneg
                (result_reneg, result_secure) = \
                    _test_renegotiation(target, self._shared_state)
                formatted_results.append('      {0:<35} {1}'.format(
                    'Client Initiated Renegotiation:',
                    result_reneg))
                formatted_results.append('      {0:<35} {1}'.format(
                    'Secure Renegotiation: ',
                    result_secure))
            except Exception as e:
                formatted_results.append('      Error => ' + str(e))
        finally:
            ctSSL_cleanup()

        return formatted_results


def _test_renegotiation(target, shared_state):
    """
    Checks whether the server honors session renegotation requests and whether
    it supports secure renegotiation.
    """
    (host, ip_addr, port) = target
    result_reneg = 'N/A'
    result_secure = 'N/A'
    ctx = SSL_CTX.SSL_CTX()

    if shared_state['cert']: # Client certificate
        load_client_certificate(ctx, shared_state)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl = SSL.SSL(ctx, sock)
    sock.settimeout(shared_state['timeout'])
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
            result_reneg = 'Enabled'

        except errors.ctSSLUnexpectedEOF as e:
            result_reneg = 'Disabled'

        except socket.error as e:
            if 'connection was forcibly closed' in str(e.args):
                result_reneg = 'Disabled'
            elif 'reset by peer' in str(e.args):
                result_reneg = 'Disabled'
            else:
                raise e

        except socket.timeout as e:
            result_reneg = 'Disabled (timeout)'

        except errors.SSLError as e:
            if 'handshake failure' in str(e.args):
                result_reneg = 'Disabled'
            elif 'no renegotiation' in str(e.args):
                result_reneg = 'Disabled'
            else:
                raise e

    finally:
        ssl.shutdown()
        sock.close()

    return (result_reneg, result_secure)