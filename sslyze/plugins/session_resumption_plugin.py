# -*- coding: utf-8 -*-
"""Plugin to analyze the server's SSL session resumption capabilities.
"""

from xml.etree.ElementTree import Element

from nassl import SSL_OP_NO_TICKET

from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginResult
from sslyze.utils.thread_pool import ThreadPool


class SessionResumptionPlugin(plugin_base.PluginBase):

    interface = plugin_base.PluginInterface(
        title="SessionResumptionPlugin",
        description="Analyzes the target server's SSL session resumption capabilities."
    )
    interface.add_command(
        command="resum",
        help="Tests the server(s) for session resumption support using session IDs and TLS session tickets (RFC 5077)."
    )
    interface.add_command(
        command="resum_rate",
        help="Performs 100 session resumptions with the server(s), in order to estimate the session resumption rate.",
        aggressive=True
    )


    MAX_THREADS_NB = 20

    def process_task(self, server_info, command, options_dict=None):

        if command == 'resum':
            result = self._command_resum(server_info)
        elif command == 'resum_rate':
            successful_resumptions_nb, errored_resumptions_list = self._test_session_resumption_rate(server_info, 100)
            result = ResumptionRateResult(server_info, command, options_dict, 100, successful_resumptions_nb,
                                          errored_resumptions_list)
        else:
            raise ValueError("PluginSessionResumption: Unknown command.")

        return result


    def _command_resum(self, server_info):
        """Tests the server for session resumption support using session IDs and TLS session tickets (RFC 5077).
        """
        # Test Session ID support
        successful_resumptions_nb, errored_resumptions_list = self._test_session_resumption_rate(server_info, 5)

        # Test TLS tickets support
        ticket_exception = None
        ticket_reason = None
        ticket_supported = False
        try:
            (ticket_supported, ticket_reason) = self._resume_with_session_ticket(server_info)
        except Exception as e:
            ticket_exception = e

        return ResumptionResult(server_info, 'resum', {}, 5,  successful_resumptions_nb, errored_resumptions_list,
                                ticket_supported, ticket_reason, ticket_exception)


    def _test_session_resumption_rate(self, server_info, resumption_attempts_nb):
        """Attempts several session ID resumption with the server."""
        thread_pool = ThreadPool()

        for _ in xrange(resumption_attempts_nb):
            thread_pool.add_job((self._resume_with_session_id, (server_info, )))
        thread_pool.start(nb_threads=min(resumption_attempts_nb, self.MAX_THREADS_NB))

        # Count successful/failed resumptions
        successful_resumptions_nb = 0
        for completed_job in thread_pool.get_result():
            (job, was_resumption_successful) = completed_job
            if was_resumption_successful:
                successful_resumptions_nb += 1

        # Count errors and store error messages
        errored_resumptions_list = []
        for failed_job in thread_pool.get_error():
            (job, exception) = failed_job
            error_msg = '{} - {}'.format(str(exception.__class__.__name__), str(exception))
            errored_resumptions_list.append(error_msg)

        thread_pool.join()
        return successful_resumptions_nb, errored_resumptions_list


    def _resume_with_session_id(self, server_info):
        """Performs one session resumption using Session IDs.
        """
        session1 = self._resume_ssl_session(server_info)
        try:
            # Recover the session ID
            session1_id = self._extract_session_id(session1)
        except IndexError:
            # Session ID not assigned
            return False

        if session1_id == '':
            # Session ID empty
            return False

        # Try to resume that SSL session
        session2 = self._resume_ssl_session(server_info, session1)
        try: # Recover the session ID
            session2_id = self._extract_session_id(session2)
        except IndexError:
            # Session ID not assigned
            return False

        # Finally, compare the two Session IDs
        if session1_id != session2_id:
            # Session ID assigned but not accepted
            return False

        return True


    def _resume_with_session_ticket(self, server_info):
        """Performs one session resumption using TLS Session Tickets.
        """
        # Connect to the server and keep the SSL session
        session1 = self._resume_ssl_session(server_info, should_enable_tls_ticket=True)
        try:
            # Recover the TLS ticket
            session1_tls_ticket = self._extract_tls_session_ticket(session1)
        except IndexError:
            return False, 'TLS ticket not assigned'

        # Try to resume that session using the TLS ticket
        session2 = self._resume_ssl_session(server_info, session1, should_enable_tls_ticket=True)
        try:
            # Recover the TLS ticket
            session2_tls_ticket = self._extract_tls_session_ticket(session2)
        except IndexError:
            return False, 'TLS ticket not assigned'

        # Finally, compare the two TLS Tickets
        if session1_tls_ticket != session2_tls_ticket:
            return False, 'TLS ticket assigned but not accepted'

        return True, ''


    @staticmethod
    def _extract_session_id(ssl_session):
        """Extracts the SSL session ID from a SSL session object or raises IndexError if the session ID was not set.
        """
        session_string = ( (ssl_session.as_text()).split("Session-ID:") )[1]
        session_id = ( session_string.split("Session-ID-ctx:") )[0].strip()
        return session_id


    @staticmethod
    def _extract_tls_session_ticket(ssl_session):
        """Extracts the TLS session ticket from a SSL session object or raises IndexError if the ticket was not set.
        """
        session_string = ((ssl_session.as_text()).split("TLS session ticket:"))[1]
        session_tls_ticket = (session_string.split("Compression:"))[0]
        return session_tls_ticket


    def _resume_ssl_session(self, server_info, ssl_session=None, should_enable_tls_ticket=False):
        """Connects to the server and returns the session object that was assigned for that connection.
        If ssl_session is given, tries to resume that session.
        """
        ssl_connection = server_info.get_preconfigured_ssl_connection()
        if not should_enable_tls_ticket:
        # Need to disable TLS tickets to test session IDs, according to rfc5077:
        # If a ticket is presented by the client, the server MUST NOT attempt
        # to use the Session ID in the ClientHello for stateful session resumption
            ssl_connection.set_options(SSL_OP_NO_TICKET) # Turning off TLS tickets.

        if ssl_session:
            ssl_connection.set_session(ssl_session)

        try: # Perform the SSL handshake
            ssl_connection.connect()
            new_session = ssl_connection.get_session() # Get session data
        finally:
            ssl_connection.close()

        return new_session


class ResumptionRateResult(PluginResult):
    """The result of running --resum_rate on a specific server.

    Attributes:
        attempted_resumptions_nb (int): The total number of session ID resumptions that were attempted.
        successful_resumptions_nb (int): The number of session ID resumptions that were successful.
        failed_resumptions_nb (int): The number of session ID resumptions that failed.
        errored_resumptions_list (Optional[List[(str)]): A list of unexpected errors triggered while trying to perform
        session ID resumption with the server (should always be empty).
    """

    COMMAND_TITLE = 'Resumption Rate'

    def __init__(self, server_info, plugin_command, plugin_options, attempted_resumptions_nb, successful_resumptions_nb,
                 errored_resumptions_list):
        super(ResumptionRateResult, self).__init__(server_info, plugin_command, plugin_options)

        self.attempted_resumptions_nb = attempted_resumptions_nb
        self.successful_resumptions_nb = successful_resumptions_nb
        self.errored_resumptions_list = errored_resumptions_list
        self.failed_resumptions_nb = attempted_resumptions_nb - successful_resumptions_nb - \
                                     len(errored_resumptions_list)


    RESUMPTION_RESULT_FORMAT = '{4} ({0} successful, {1} failed, {2} errors, {3} total attempts).'.format
    RESUMPTION_LINE_FORMAT = '      {resumption_type:<35}{result}'.format
    RESUMPTION_ERROR_FORMAT = '        ERROR #{error_nb}: {error_msg}'.format

    def as_text(self):
        result_txt = [self.PLUGIN_TITLE_FORMAT(self.COMMAND_TITLE)]

        # Create the line which summarizes the session resumption rate
        if self.successful_resumptions_nb == self.attempted_resumptions_nb:
            resumption_supported_txt = 'OK - Supported'
        elif self.successful_resumptions_nb > 0:
            resumption_supported_txt = 'PARTIALLY SUPPORTED'
        elif self.failed_resumptions_nb == self.attempted_resumptions_nb:
            resumption_supported_txt = 'NOT SUPPORTED'
        else:
            resumption_supported_txt = 'ERROR'

        resum_rate_txt = self.RESUMPTION_RESULT_FORMAT(str(self.successful_resumptions_nb),
                                                      str(self.failed_resumptions_nb),
                                                      str(len(self.errored_resumptions_list)),
                                                      str(self.attempted_resumptions_nb),
                                                      resumption_supported_txt)
        result_txt.append(self.RESUMPTION_LINE_FORMAT(resumption_type='With Session IDs:', result=resum_rate_txt))

        # Add error messages if there was any
        i = 0
        for error_msg in self.errored_resumptions_list:
            result_txt.append(self.RESUMPTION_ERROR_FORMAT(error_nb=i, error_msg=error_msg))
            i += 1

        return result_txt


    def as_xml(self):
        xml_result = Element(self.plugin_command, title=self.COMMAND_TITLE)

        resumption_rate_xml = Element(
                'sessionResumptionWithSessionIDs',
                attrib={'totalAttempts': str(self.attempted_resumptions_nb),
                        'errors': str(len(self.errored_resumptions_list)),
                        'isSupported': str(self.attempted_resumptions_nb == self.successful_resumptions_nb),
                        'successfulAttempts': str(self.successful_resumptions_nb),
                        'failedAttempts': str(self.failed_resumptions_nb)}
        )
        # Add error messages if there was any
        for error_msg in self.errored_resumptions_list:
            resumption_error_xml = Element('error')
            resumption_error_xml.text = error_msg
            resumption_rate_xml.append(resumption_error_xml)

        xml_result.append(resumption_rate_xml)
        return xml_result



class ResumptionResult(ResumptionRateResult):
    """The result of running --resum on a specific server; also has all the attributes of ResumptionRateResult.

    Attributes:
        is_ticket_resumption_supported (bool): True if the server honors client-initiated renegotiation attempts.
        ticket_resumption_failed_reason (str): A message explaining why TLS ticket resumption failed.
        ticket_resumption_exception (Optional[str]): An unexpected error that was raised while trying to perform ticket
            resumption (should never happen).
    """

    def __init__(self, server_info, plugin_command, plugin_options, attempted_resumptions_nb, successful_resumptions_nb,
                 errored_resumptions_list, is_ticket_resumption_supported, ticket_resumption_failed_reason=None,
                 ticket_resumption_exception=None):

        super(ResumptionResult, self).__init__(server_info, plugin_command, plugin_options,
                                               attempted_resumptions_nb, successful_resumptions_nb,
                                               errored_resumptions_list)

        self.is_ticket_resumption_supported = is_ticket_resumption_supported
        self.ticket_resumption_failed_reason = ticket_resumption_failed_reason

        # An exception was raised while trying to perform ticket resumption (should never happen)
        self.ticket_resumption_error = None
        if ticket_resumption_exception:
            self.ticket_resumption_error = '{} - {}'.format(str(ticket_resumption_exception.__class__.__name__),
                                                            str(ticket_resumption_exception))

    COMMAND_TITLE = 'Session Resumption'

    def as_text(self):
        # Same output as --resum_rate but add a line about TLS ticket resumption at the end
        result_txt = super(ResumptionResult, self).as_text()

        if self.ticket_resumption_error:
            ticket_txt = 'ERROR: {}'.format(self.ticket_resumption_error)
        else:
            ticket_txt = 'OK - Supported' \
                if self.is_ticket_resumption_supported \
                else 'NOT SUPPORTED - {}.'.format(self.ticket_resumption_failed_reason)


        result_txt.append(self.RESUMPTION_LINE_FORMAT(resumption_type='With TLS Tickets:', result=ticket_txt))
        return result_txt


    def as_xml(self):
        xml_result = Element(self.plugin_command, title=self.COMMAND_TITLE)

        # We keep the session resumption XML node
        resum_rate_xml = super(ResumptionResult, self).as_xml()
        session_resum_xml = resum_rate_xml[0]
        xml_result.append(session_resum_xml)

        # Add the ticket resumption node
        xml_resum_ticket_attr = {}
        if self.ticket_resumption_error:
            xml_resum_ticket_attr['error'] = self.ticket_resumption_error
        else:
            xml_resum_ticket_attr['isSupported'] = str(self.is_ticket_resumption_supported)
            if not self.is_ticket_resumption_supported:
                xml_resum_ticket_attr['reason'] = self.ticket_resumption_failed_reason

        xml_resum_ticket = Element('sessionResumptionWithTLSTickets', attrib=xml_resum_ticket_attr)
        xml_result.append(xml_resum_ticket)

        return xml_result