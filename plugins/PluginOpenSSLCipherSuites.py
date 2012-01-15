#!/usr/bin/env python
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


import socket
from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.ctSSL import SSL, SSL_CTX, constants, ctSSL_initialize, \
    ctSSL_cleanup
from utils.CtSSLHelper import create_https_connection
from utils.HTTPSConnection import SSLHandshakeFailed



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
        ctx = SSL_CTX.SSL_CTX(ssl_version)
        ctx.set_cipher_list('ALL:NULL:@STRENGTH')
        ssl = SSL.SSL(ctx)
        cipher_list = ssl.get_cipher_list()

        # Create a thread pool
        NB_THREADS = min(len(cipher_list), MAX_THREADS) # One thread per cipher
        thread_pool = ThreadPool()

        # Scan for every available cipher suite
        for cipher in cipher_list:
            thread_pool.add_job((_test_ciphersuite,
                (target, ssl_version, cipher, self._shared_settings)))

        # Scan for the preferred cipher suite
        thread_pool.add_job((_pref_ciphersuite,
           (target, ssl_version, self._shared_settings)))

        # Start processing the jobs
        thread_pool.start(NB_THREADS)

        # Process the results as they come
        test_ciphers_results = {}
        possible_results = ['Preferred','Accepted','Rejected', 'Errors']
        for result_type in possible_results:
            test_ciphers_results[result_type] = {}
            
        for completed_job in thread_pool.get_result():
            (job, result) = completed_job
            if result is not None:
                (ssl_cipher, result, msg) = result
                (test_ciphers_results[result])[ssl_cipher] = msg
                    

        # Format the results to make them printable
        cipher_format = '        {0:<32}{1:<35}'
        title_format =  '      {0:<32} '
        formatted_results = [
            ('  * {0} Cipher Suites :'.format(ssl_version.upper()))]
        
        # Print each dictionnary of results 
        for result_type in possible_results:
            if len(test_ciphers_results[result_type]) != 0:
                # Print accepted cipher suites
                formatted_results.append('') # New line
                
                if result_type == 'Errors':
                    formatted_results.append(
                        title_format.format('Errors:'))
                else:
                    formatted_results.append(
                        title_format.format(result_type + ' Cipher Suites:'))
                    
                formatted_results.extend(
                    _format_cipher_results(
                        cipher_format, 
                        test_ciphers_results[result_type]) )

        # Process errors
        for failed_job in thread_pool.get_error():
            (job, exception) = failed_job
            formatted_results.append(
                cipher_format.format(str((job[1])[2]),
                ' Error => ' + str(exception)))
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
    for (ssl_cipher, (msg) ) in result_list:
        printable_results.append(
            result_format.format(ssl_cipher, msg) )
    return printable_results


def _test_ciphersuite(target, ssl_version, ssl_cipher, shared_settings):
    """
    Initiates a SSL handshake with the server, using the SSL version and cipher
    suite specified.
    """
    ssl_ctx = SSL_CTX.SSL_CTX(ssl_version)
    ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
    ssl_ctx.set_cipher_list(ssl_cipher)

    https_connect = \
        create_https_connection(target, shared_settings, ssl_ctx=ssl_ctx)
    
    try: # Perform the SSL handshake
        https_connect.connect()
    except SSLHandshakeFailed as e:
        return (ssl_cipher, 'Rejected', str(e))
    except Exception as e:
        return (ssl_cipher, 'Errors', str(e.__class__.__module__) + '.' + str(e.__class__.__name__) + ' - ' + str(e))

    else:
        ssl_cipher = https_connect.ssl.get_current_cipher()
        
        # Add key length or ANON to the cipher name
        cipher_format = '{0:<25}{1:<14}'
        if 'ADH' in ssl_cipher or 'AECDH' in ssl_cipher:
            ssl_cipher = cipher_format.format(ssl_cipher, 'Anon')
        else:
            ssl_cipher = cipher_format.format(ssl_cipher,  str(https_connect.ssl.get_current_cipher_bits()) + ' bits')
               
            
        try: 
            # Send an HTTP GET to the server and store the HTTP Status Code
            https_connect.request("GET", "/", headers={"Connection": "close"})
            http_response = https_connect.getresponse()
            result_http_get = 'HTTP ' \
                + str(http_response.status) \
                + ' ' \
                + str(http_response.reason)
            return (ssl_cipher, 'Accepted', result_http_get)
        except socket.timeout:
            return (ssl_cipher, 'Accepted', 'Timeout')

    finally:
        https_connect.close()
        
    return

def _pref_ciphersuite(target, ssl_version, shared_settings):
    """
    Initiates a SSL handshake with the server, using the SSL version specified,
    and returns the server's preferred cipher suite or None if the connection
    failed.
    """
    ssl_ctx = SSL_CTX.SSL_CTX(ssl_version)
    ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
    ssl_ctx.set_cipher_list('ALL:NULL:@STRENGTH') # Explicitely allow all ciphers

    https_connect = \
        create_https_connection(target, shared_settings, ssl_ctx=ssl_ctx)
    
    try: # Perform the SSL handshake
        https_connect.connect()
    except Exception:
        return None

    else:
        ssl_cipher = https_connect.ssl.get_current_cipher()
        
        # Add key length or ANON to the cipher name
        cipher_format = '{0:<25}{1:<14}'
        if 'ADH' in ssl_cipher or 'AECDH' in ssl_cipher:
            ssl_cipher = cipher_format.format(ssl_cipher, 'Anon')
        else:
            ssl_cipher = cipher_format.format(ssl_cipher,  str(https_connect.ssl.get_current_cipher_bits()) + ' bits')
            
        try: 
            # Send an HTTP GET to the server and store the HTTP Status Code
            https_connect.request("GET", "/", headers={"Connection": "close"})
            http_response = https_connect.getresponse()
            result_http_get = 'HTTP ' \
                + str(http_response.status) \
                + ' ' \
                + str(http_response.reason)
            return (ssl_cipher, 'Preferred', result_http_get)
        except socket.timeout:
            return (ssl_cipher, 'Preferred', 'Timeout')

    finally:
        https_connect.close()
        
    return