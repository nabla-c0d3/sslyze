#-------------------------------------------------------------------------------
# Name:         PluginOpenSSLCipherSuites.py
# Purpose:      Scans the target server for supported OpenSSL cipher suites.
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
from utils.ThreadPool import ThreadPool
from utils.ctSSL import SSL, SSL_CTX, constants, ctSSL_initialize, \
    errors, ctSSL_cleanup
from utils.CtSSLHelper import FailedSSLHandshake, do_ssl_handshake, \
    get_http_server_response, load_client_certificate


class PluginOpenSSLCipherSuites(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        "PluginOpenSSLCipherSuites",
        "Scans the target server for supported OpenSSL cipher suites.")
    available_commands.add_option(
        command="sslv2",
        help="Lists the SSL 2.0 OpenSSL cipher suites supported by the server.",
        dest=None)
    available_commands.add_option(
        command="sslv3",
        help="Lists the SSL 3.0 OpenSSL cipher suites supported by the server.",
        dest=None)
    available_commands.add_option(
        command="tlsv1",
        help="Lists the TLS 1.0 OpenSSL cipher suites supported by the server.",
        dest=None)


    def process_task(self, target, command, args):

        MAX_THREADS = 50
        if command in ['sslv2', 'sslv3', 'tlsv1']:
            ssl_version = command
        else:
            raise Exception("PluginOpenSSLCipherSuites: Unknown command.")

        # Get the list of available cipher suites for the given ssl version
        ctSSL_initialize(multithreading=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try: # Ubuntu sometimes has ssl2 disabled. It would crash here.
            ctx = SSL_CTX.SSL_CTX(ssl_version)
        except errors.OpenSSLError as e:
            if 'null ssl method passed' in str(e.args):
                if ssl_version == 'sslv2': # Def. Ubuntu with ssl2 disabled
                    formatted_results = []
                    formatted_results.append(
                        ('  * Supported {0} Cipher Suite(s):'
                        'Could not initialize SSLv2 context. Using Ubuntu with'
                        'SSL2 disabled ?').format(ssl_version.upper()))
                    return formatted_results

        ctx.set_cipher_list('ALL:NULL:@STRENGTH')
        ssl = SSL.SSL(ctx, sock)
        cipher_list = ssl.get_cipher_list()

        # Create a thread pool
        NB_THREADS = min(len(cipher_list), MAX_THREADS) # One thread per cipher
        thread_pool = ThreadPool()

        # Scan for every available cipher suite
        for cipher in cipher_list:
            thread_pool.add_job((_test_ciphersuite,
                (target, ssl_version, cipher, self._shared_state)))

        # Scan for the preferred cipher suite
        thread_pool.add_job((_test_ciphersuite,
            (target, ssl_version, None, self._shared_state)))

        # Start processing the jobs
        thread_pool.start(NB_THREADS)

        # Process the results as they come
        accepted_ciphers = {}
        rejected_ciphers = {}
        for completed_job in thread_pool.get_result():
             (job, result) = completed_job
             if result is not None:
                 (ssl_cipher, result_ssl , result_http_get) = result
                 if result_ssl == 'Accepted':
                    # Store the result without overwriting the Preferred cipher
                    accepted_ciphers.setdefault(
                        ssl_cipher,
                        (result_ssl, result_http_get))
                 elif result_ssl == 'Preferred':
                    accepted_ciphers[ssl_cipher] = (result_ssl, result_http_get)
                 else:
                    rejected_ciphers[ssl_cipher] = (result_ssl, result_http_get)

        # Format the results to make them printable
        line_format = '      {0:<32}{1:^35}{2:^10}'
        formatted_results = [
            ('  * {0} Cipher Suites :'.format(ssl_version.upper())),
            line_format.format('Cipher Suite:', 'SSL Handshake:', 'HTTP GET:') ]
        formatted_results.extend(
            _format_cipher_results(line_format, accepted_ciphers) )
        formatted_results.extend(
            _format_cipher_results(line_format, rejected_ciphers) )

        # Process errors
        for failed_job in thread_pool.get_error():
            (job, exception) = failed_job
            formatted_results.append(
                line_format.format(str((job[1])[2]),
                ' Error => ' + str(exception),''))
        thread_pool.join()
        ctSSL_cleanup()
        return formatted_results


# == INTERNAL FUNCTIONS ==
def _format_cipher_results(result_format, result_dict):
    """
    Extract results from a result dictionnary and make those results printable.
    """
    printable_results = []
    # Sorting the cipher suites by result
    result_list = sorted(result_dict.iteritems(), key=lambda (k,v): (v,k),
        reverse=True)
    for (ssl_cipher, (result_ssl, result_http_get) ) in result_list:
        printable_results.append(
            result_format.format(ssl_cipher, result_ssl, result_http_get) )
    return printable_results


def _test_ciphersuite(target, ssl_version, ssl_cipher, shared_state):
    """
    Initiates a SSL handshake with the server, using the SSL version and cipher
    suite specified. If no ssl_cipher is None, will connect to the server
    and return its preferred cipher suite.
    """
    (host, ip_addr, port) = target
    ctx = SSL_CTX.SSL_CTX(ssl_version)
    ctx.set_verify(constants.SSL_VERIFY_NONE)

    if ssl_cipher: # Testing one specific cipher
        ctx.set_cipher_list(ssl_cipher)
        result_success = 'Accepted'
    else: # Testing for the server's preferred cipher suite
        result_success = 'Preferred'

    if shared_state['cert']: # Load client certificate
        load_client_certificate(ctx, shared_state)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl = SSL.SSL(ctx, sock)
    sock.settimeout(shared_state['timeout'])

    try: # Initiate a TCP connection
        sock.connect((ip_addr, port))
    except socket.timeout:
        if ssl_cipher:
            return (ssl_cipher, 'Failed - Timeout', 'N/A')

    try: # Perform the SSL handshake
        do_ssl_handshake(ssl)

    except FailedSSLHandshake as e:
        if ssl_cipher:
            return (ssl_cipher, str(e), 'N/A')

    except Exception as e:
        if ssl_cipher:
            return (ssl_cipher, 'Error ' + str(type(e)) + ': ' + str(e), 'N/A')

    else:
        ssl_cipher = ssl.get_current_cipher()
        # Add key length or ANON to the cipher name
        if 'ADH' in ssl_cipher or 'AECDH' in ssl_cipher:
            ssl_cipher += '  Anon'
        else:
            ssl_cipher += '  ' + str(ssl.get_current_cipher_bits()) + 'bits'
        try: # Send an HTTP GET to the server and store the HTTP Status Code
            result_http_get = get_http_server_response(ssl, host)
            return (ssl_cipher , result_success, result_http_get)
        except socket.timeout:
            return (ssl_cipher, result_success, 'Timeout')

    finally:
        ssl.shutdown()
        sock.close()

    return
