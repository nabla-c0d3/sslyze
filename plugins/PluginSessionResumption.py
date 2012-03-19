#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginSessionResumption.py
# Purpose:      Analyzes the server's SSL session resumption capabilities.
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

from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.ctSSL import SSL_CTX, constants, ctSSL_initialize, ctSSL_cleanup
from utils.CtSSLHelper import SSLHandshakeRejected


class PluginSessionResumption(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginSessionResumption",
        description=(
            "Analyzes the target server's SSL session "
            "resumption capabilities."))
    available_commands.add_option(
        command="resum",
        help=(
            "Tests the server for session ressumption support, using "
            "session IDs and TLS session tickets (RFC 5077)."),
        dest=None)
    available_commands.add_option(
        command="resum_rate",
        help=(
            "Performs 100 session resumptions with the target server, "
            "in order to estimate the session resumption rate."),
        dest=None)


    def process_task(self, target, command, args):

        ctSSL_initialize(multithreading=True)
        try:
            if command == 'resum':
                result = self._command_resum(target)
            elif command == 'resum_rate':
                result = self._command_resum_rate(target)
            else:
                raise Exception("PluginSessionResumption: Unknown command.")
        finally:
            ctSSL_cleanup()
        return result


    def _command_resum_rate(self, target):
        """
        Performs 100 session resumptions with the server in order to estimate
        the session resumption rate.
        """
        # Create a thread pool and process the jobs
        NB_THREADS = 50
        NB_RESUM = 100
        thread_pool = ThreadPool()
        for i in xrange(NB_RESUM):
            thread_pool.add_job((
                self._test_resumption_with_session_id,
                (target, ('sslv3'))))
        thread_pool.start(NB_THREADS)

        # Count successful resumptions
        sucessful_resumptions = 0
        for completed_job in thread_pool.get_result():
            (job, result_string) = completed_job
            if result_string == 'Supported':
                sucessful_resumptions += 1

        result_string = str(sucessful_resumptions) + \
            ' resumptions successful out of ' + str(NB_RESUM) + ' attempts.'

        error_list = []
        for failed_job in thread_pool.get_error():
            error_list.append(failed_job)
        if error_list:
            result_string += ' Errors were encountered.'

        formatted_results = [
            '  * {0} : {1}'.format('Session Resumption Rate', result_string)]

        thread_pool.join()
        return formatted_results


    def _command_resum(self, target):
        """
        Tests the server for session ressumption support, using session IDs and
        TLS session tickets (RFC 5077).
        """
        NB_THREADS = 3
        thread_pool = ThreadPool()
        thread_pool.add_job((
            self._test_resumption_with_session_ticket,
            (target, None),
            'Using TLSv1 Session Tickets: '))
        thread_pool.add_job((
            self._test_resumption_with_session_id,
            (target,('sslv3')),
            'Using SSLv3 Session IDs: '))
        thread_pool.add_job((
            self._test_resumption_with_session_id,
            (target,('tlsv1')),
            'Using TLSv1 Session IDs: '))
        thread_pool.start(NB_THREADS)

        formatted_results = ['  * {0} :'.format('Session Resumption')]
        for completed_job in thread_pool.get_result():
            (job, result_string) = completed_job
            formatted_results.append(
                '      {0:<30} {1}'.format(job[2], result_string))

        for failed_job in thread_pool.get_error():
            (job, excep) = failed_job
            formatted_results.append(
                '      {0:<30} {1}'.format(job[2],  'Error => ' + str(excep)))

        thread_pool.join()
        return formatted_results


    # == INTERNAL FUNCTIONS ==

    def _test_resumption_with_session_id(self, target, ssl_version):
        """
        Tests the server for session resumption support using Session IDs.
        """
        try:
            self._resume_with_session_id(target, ssl_version)
            result = 'Supported'
        except FailedSessionResumption as e:
            result = e[0]
    
        return result
    
    
    def _test_resumption_with_session_ticket(self, target, args):
        """
        Tests the server for session resumption support using TLS Tickets.
        """
        try:
            self._resume_with_session_ticket(target)
            result = 'Supported'
        except FailedSessionResumption as e:
            result = e[0]
    
        return result
    
    
    def _resume_with_session_id(self, target, ssl_version):
        """
        Performs one session resumption using Session IDs.
        Raises FailedSessionResumption if resumption failed.
        """
        ctx = SSL_CTX.SSL_CTX(ssl_version)
        ctx.set_verify(constants.SSL_VERIFY_NONE)
        #ctx.set_cipher_list('ALL:NULL:@STRENGTH') # Explicitely allow all ciphers
        # All ciphers + non empty session ID field make the TLSv1 client hello
        # larger than 255 bytes, making lots of servers on the Internet
        # not answer our hello :(
    
        # Session Tickets and Session ID mechanisms can be mutually exclusive.
        ctx.set_options(constants.SSL_OP_NO_TICKET) # Turning off TLS tickets.
    
        try: # Connect to the server and keep the SSL session
            session1 = self._resume_ssl_session(target, ctx)
        except SSLHandshakeRejected as e:
            raise SSLHandshakeRejected('SSL Handshake failed: ' + e[0])
    
        try: # Recover the session ID
            session1_id = self._extract_session_id(session1)
        except IndexError as e:
            raise FailedSessionResumption('Not Supported (Session ID not assigned)')
    
        # Try to resume that SSL session
        try:
            session2 = self._resume_ssl_session(target, ctx, session1)
        except SSLHandshakeRejected as e:
            raise SSLHandshakeRejected('SSL Handshake failed: ' + e[0])
    
        try: # Recover the session ID
            session2_id = self._extract_session_id(session2)
        except IndexError as e:
            raise FailedSessionResumption('Not Supported (Session ID not assigned)')
    
        # Finally, compare the two Session IDs
        if session1_id != session2_id:
            raise FailedSessionResumption(
                'Not Supported (Session ID assigned but not accepted; try --resum_rate)')
    
        return
    
    
    def _resume_with_session_ticket(self, target):
        """
        Performs one session resumption using TLS Session Tickets.
        Raises FailedSessionResumption if resumption failed.
        """
        ctx = SSL_CTX.SSL_CTX('tlsv1')
        ctx.set_verify(constants.SSL_VERIFY_NONE)
        ctx.set_cipher_list('ALL:NULL:@STRENGTH') # Explicitely allow all ciphers
    
        # Session Tickets and Session ID mechanisms can be mutually exclusive.
        ctx.set_session_cache_mode(constants.SSL_SESS_CACHE_OFF) # Turning off IDs.
    
        try: # Connect to the server and keep the SSL session
            session1 =self._resume_ssl_session(target, ctx)
        except SSLHandshakeRejected as e:
            raise FailedSessionResumption('SSL Handshake failed: ' + e[0])
    
        try: # Recover the TLS ticket
            session1_tls_ticket = self._extract_tls_session_ticket(session1)
        except IndexError:
            raise FailedSessionResumption('Not Supported (TLS ticket not assigned)')
    
        # Try to resume that session using the TLS ticket
        try:
            session2 = self._resume_ssl_session(target, ctx, session1)
        except SSLHandshakeRejected as e:
            raise FailedSessionResumption('SSL Handshake failed: ' + e[0])
    
        try: # Recover the TLS ticket
            session2_tls_ticket = self._extract_tls_session_ticket(session2)
        except IndexError:
            raise FailedSessionResumption('Not Supported (TLS ticket not assigned)')
    
        # Finally, compare the two TLS Tickets
        if session1_tls_ticket != session2_tls_ticket:
            raise FailedSessionResumption(
                'Not Supported (TLS ticket assigned but not accepted)')
    
        return
    
    
    def _extract_session_id(self, ssl_session):
        """
        Extracts the SSL session ID from a SSL session object or raises IndexError
        if the session ID was not set.
        """
        session_string = ( (ssl_session.as_text()).split("Session-ID:") )[1]
        session_id = ( session_string.split("Session-ID-ctx:") )[0]
        return session_id
    
    
    def _extract_tls_session_ticket(self, ssl_session):
        """
        Extracts the TLS session ticket from a SSL session object or raises
        IndexError if the ticket was not set.
        """
        session_string = ( (ssl_session.as_text()).split("TLS session ticket:") )[1]
        session_tls_ticket = ( session_string.split("Compression:") )[0]
        return session_tls_ticket
    
    
    def _resume_ssl_session(self, target, ssl_ctx, ssl_session = None):
        """
        Connect to the server and returns the session object that was assigned 
        for that connection.
        If ssl_session is given, tries to resume that session.
        """
        ssl_connect = self._create_ssl_connection(target, ssl_ctx=ssl_ctx)
    
        if ssl_session:
            ssl_connect.ssl.set_session(ssl_session)
    
        try: # Perform the SSL handshake
            ssl_connect.connect()
            session = ssl_connect.ssl.get_session() # Get session data
        except SSLHandshakeRejected:
            raise
        finally:
            ssl_connect.close()
            
        return session


class FailedSessionResumption(Exception):
    pass
