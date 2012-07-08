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
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.ctSSL import SSL_CTX, constants, ctSSL_initialize, ctSSL_cleanup


class PluginSessionResumption(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginSessionResumption",
        description=(
            "Analyzes the target server's SSL session "
            "resumption capabilities."))
    available_commands.add_command(
        command="resum",
        help=(
            "Tests the server for session ressumption support, using "
            "session IDs and TLS session tickets (RFC 5077)."),
        dest=None)
    available_commands.add_command(
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
        NB_THREADS = 20
        MAX_RESUM = 100
        thread_pool = ThreadPool()
        for i in xrange(MAX_RESUM):
            thread_pool.add_job((self._resume_with_session_id, 
                                 (target, ('tlsv1'))))
        thread_pool.start(NB_THREADS)

        # Count successful resumptions      
        (nb_resum, nb_error) = self._count_resumptions(thread_pool)
        nb_failed = MAX_RESUM - nb_error - nb_resum

        # Text output
        resum_format = '{0} successful, {1} failed, {2} errors, {3} total attempts.'
        resum_txt = resum_format.format(str(nb_resum), str(nb_failed), 
                          str(nb_error), str(MAX_RESUM))
        
        cmd_title = 'Resumption Rate with Session IDs'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)+' '+resum_txt]

        # XML output
        xml_resum_attr = {'total' : str(MAX_RESUM),'successful' : str(nb_resum),
                          'failed' : str(nb_failed), 'errors' : str(nb_error)}
        
        xml_resum = Element('resum_rate', attrib = xml_resum_attr)  
        xml_result = Element(self.__class__.__name__, command = 'resum_rate',
                             title = cmd_title)
        xml_result.append(xml_resum)

        thread_pool.join()
        return PluginBase.PluginResult(txt_result, xml_result)
        

    def _command_resum(self, target):
        """
        Tests the server for session resumption support using session IDs and
        TLS session tickets (RFC 5077).
        """
        NB_THREADS = 5
        MAX_RESUM = 5
        thread_pool = ThreadPool()
        
        for i in xrange(MAX_RESUM): # Test 5 resumptions with session IDs
            thread_pool.add_job((self._resume_with_session_id,
                                 (target,('tlsv1')), 'session_id'))
        thread_pool.start(NB_THREADS)
        
        # Test TLS tickets support while threads are running
        try:
            (ticket_supported, ticket_reason) = self._resume_with_session_ticket(target)
            ticket_error = None
        except Exception as e:
            ticket_error = str(e.__class__.__module__) + '.' + \
                            str(e.__class__.__name__) + ' - ' + str(e)
                            
        # Count successful resumptions      
        (nb_resum, nb_error) = self._count_resumptions(thread_pool)
        nb_failed = MAX_RESUM - nb_error - nb_resum
            
        # Text output
        sessid_format = '{4} ({0} successful, {1} failed, {2} errors, {3} total attempts).{5}'
        sessid_try = '' 
        if nb_resum == MAX_RESUM:
            sessid_stat = 'Supported'
        elif nb_failed == MAX_RESUM:
            sessid_stat = 'Not supported'
        elif nb_error == MAX_RESUM:
            sessid_stat = 'Error'
        else:
            sessid_stat = 'Partially supported'
            sessid_try = ' Try --resum_rate.'
        sessid_txt = sessid_format.format(str(nb_resum), str(nb_failed), 
                                  str(nb_error), str(MAX_RESUM),
                                  sessid_stat, sessid_try)
        
        if ticket_error:
            ticket_txt = 'Error: ' + ticket_error
        else:
            ticket_txt = 'Supported' if ticket_supported \
                                     else 'Not Supported - ' + ticket_reason+'.'
        
        cmd_title = 'Session Resumption'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        RESUM_FORMAT = '      {0:<27} {1}'
        txt_result.append(RESUM_FORMAT.format('With Session IDs:', sessid_txt))
        txt_result.append(RESUM_FORMAT.format('With TLS Session Tickets:', ticket_txt))
        
        # XML output
        sessid_xml = str(nb_resum == MAX_RESUM)
        
        xml_resum_id_attr = {'mechanism' :'session ids','total':str(MAX_RESUM), 
                             'errors' : str(nb_error), 'supported' : sessid_xml,
                             'successful':str(nb_resum),'failed':str(nb_failed)}
        xml_resum_id = Element('resum', attrib = xml_resum_id_attr)

        xml_resum_ticket_attr = {'mechanism' : 'tls tickets'}
        if ticket_error:
            xml_resum_ticket_attr['error'] = ticket_error
        else:
            xml_resum_ticket_attr['supported'] = str(ticket_supported)
            if not ticket_supported:
                xml_resum_ticket_attr['reason'] = ticket_reason
        
        xml_resum_ticket = Element('resum', attrib = xml_resum_ticket_attr)   
        xml_result = Element(self.__class__.__name__, command='resum', title=cmd_title)
        xml_result.append(xml_resum_id)
        xml_result.append(xml_resum_ticket)

        thread_pool.join()
        return PluginBase.PluginResult(txt_result, xml_result)


    def _count_resumptions(self, thread_pool):
        """
        Utility function to count the number of resumptions that were successful
        by looking at the result of a thread_pool of _resume_with_session_id()
        workers.
        """
        # Count successful/failed resumptions
        nb_resum = 0
        for completed_job in thread_pool.get_result():
            (job, (is_supported, reason_str)) = completed_job
            if is_supported: 
                nb_resum += 1
                
        # Count errors
        error_list = []
        for failed_job in thread_pool.get_error():
            error_list.append(failed_job)
        nb_error = len(error_list)
        
        return (nb_resum, nb_error)


    def _resume_with_session_id(self, target, ssl_version):
        """
        Performs one session resumption using Session IDs.
        """
        ctx = SSL_CTX.SSL_CTX(ssl_version)
        ctx.set_verify(constants.SSL_VERIFY_NONE)
        ctx.set_cipher_list(self.hello_workaround_cipher_list)

        # Session Tickets and Session ID mechanisms can be mutually exclusive.
        ctx.set_options(constants.SSL_OP_NO_TICKET) # Turning off TLS tickets.
    
        session1 = self._resume_ssl_session(target, ctx) 
        try: # Recover the session ID
            session1_id = self._extract_session_id(session1)
        except IndexError:
            return (False, 'Session ID not assigned')
    
        # Try to resume that SSL session
        session2 = self._resume_ssl_session(target, ctx, session1)
        try: # Recover the session ID
            session2_id = self._extract_session_id(session2)
        except IndexError:
            return (False, 'Session ID not assigned')
    
        # Finally, compare the two Session IDs
        if session1_id != session2_id:
            return (False, 'Session ID assigned but not accepted')
    
        return (True, '')
    
    
    def _resume_with_session_ticket(self, target):
        """
        Performs one session resumption using TLS Session Tickets.
        """
        ctx = SSL_CTX.SSL_CTX('tlsv1')
        ctx.set_verify(constants.SSL_VERIFY_NONE)
        ctx.set_cipher_list(self.hello_workaround_cipher_list)
    
        # Session Tickets and Session ID mechanisms can be mutually exclusive.
        ctx.set_session_cache_mode(constants.SSL_SESS_CACHE_OFF) # Turning off IDs.
    
        #try: # Connect to the server and keep the SSL session
        session1 = self._resume_ssl_session(target, ctx)
        try: # Recover the TLS ticket
            session1_tls_ticket = self._extract_tls_session_ticket(session1)
        except IndexError:
            return (False, 'TLS ticket not assigned')
    
        # Try to resume that session using the TLS ticket
        session2 = self._resume_ssl_session(target, ctx, session1)
        try: # Recover the TLS ticket
            session2_tls_ticket = self._extract_tls_session_ticket(session2)
        except IndexError:
            return (False, 'TLS ticket not assigned')
    
        # Finally, compare the two TLS Tickets
        if session1_tls_ticket != session2_tls_ticket:
            return (False, 'TLS ticket assigned but not accepted')

        return (True, '')
    
    
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
        finally:
            ssl_connect.close()
            
        return session
