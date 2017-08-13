# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from xml.etree.ElementTree import Element
import nassl
from enum import Enum

from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.utils.thread_pool import ThreadPool
from typing import List
from typing import Optional
from typing import Text
from typing import Tuple


class SessionResumptionSupportScanCommand(plugin_base.PluginScanCommand):
    """Test the server(s) for session resumption support using session IDs and TLS session tickets (RFC 5077).
    """

    @classmethod
    def get_cli_argument(cls):
        return 'resum'

    @classmethod
    def get_title(cls):
        return 'Resumption Support'


class SessionResumptionRateScanCommand(plugin_base.PluginScanCommand):
    """Perform 100 session ID resumptions with the server(s), in order to estimate the rate for successful resumptions.
    """

    @classmethod
    def get_cli_argument(cls):
        return 'resum_rate'

    @classmethod
    def get_title(cls):
        return 'Resumption Rate'

    @classmethod
    def is_aggressive(cls):
        return True


class TslSessionTicketSupportEnum(Enum):
    SUCCEEDED = 1
    FAILED_TICKET_NOT_ASSIGNED = 2
    FAILED_TICKED_IGNORED = 3


class SessionResumptionPlugin(plugin_base.Plugin):
    """Analyze the server(s) SSL session resumption capabilities.
    """

    MAX_THREADS_NB = 20

    @classmethod
    def get_available_commands(cls):
        return [SessionResumptionSupportScanCommand, SessionResumptionRateScanCommand]


    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, plugin_base.PluginScanCommand) -> PluginScanResult
        if scan_command.__class__ == SessionResumptionSupportScanCommand:
            # Test Session ID support
            successful_resumptions_nb, errored_resumptions_list = self._test_session_resumption_rate(server_info, 5)

            # Test TLS tickets support
            ticket_exception = None
            ticket_reason = None
            ticket_supported = False
            try:
                ticket_result = self._resume_with_session_ticket(server_info)
                if ticket_result == TslSessionTicketSupportEnum.SUCCEEDED:
                    ticket_supported = True
                else:
                    ticket_reason = 'TLS ticket not assigned' \
                        if ticket_result == TslSessionTicketSupportEnum.FAILED_TICKET_NOT_ASSIGNED \
                        else 'TLS ticket assigned but not accepted'
            except Exception as e:
                ticket_exception = e

            result = SessionResumptionSupportScanResult(server_info, scan_command, 5, successful_resumptions_nb,
                                                        errored_resumptions_list, ticket_supported, ticket_reason,
                                                        ticket_exception)

        elif scan_command.__class__ == SessionResumptionRateScanCommand:
            successful_resumptions_nb, errored_resumptions_list = self._test_session_resumption_rate(server_info, 100)
            result = SessionResumptionRateScanResult(server_info, scan_command, 100, successful_resumptions_nb,
                                                     errored_resumptions_list)
        else:
            raise ValueError('PluginSessionResumption: Unknown command.')

        return result


    def _test_session_resumption_rate(self, server_info, resumption_attempts_nb):
        # type: (ServerConnectivityInfo, int) -> Tuple[int, List[Text]]
        """Attempt several session ID resumption with the server.
        """
        thread_pool = ThreadPool()

        for _ in range(resumption_attempts_nb):
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
        # type: (ServerConnectivityInfo) -> bool
        """Perform one session resumption using Session IDs.
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
        try:
            # Recover the session ID
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
        # type: (ServerConnectivityInfo) -> TslSessionTicketSupportEnum
        """Perform one session resumption using TLS Session Tickets.
        """
        # Connect to the server and keep the SSL session
        session1 = self._resume_ssl_session(server_info, should_enable_tls_ticket=True)
        try:
            # Recover the TLS ticket
            session1_tls_ticket = self._extract_tls_session_ticket(session1)
        except IndexError:
            return TslSessionTicketSupportEnum.FAILED_TICKET_NOT_ASSIGNED

        # Try to resume that session using the TLS ticket
        session2 = self._resume_ssl_session(server_info, session1, should_enable_tls_ticket=True)
        try:
            # Recover the TLS ticket
            session2_tls_ticket = self._extract_tls_session_ticket(session2)
        except IndexError:
            return TslSessionTicketSupportEnum.FAILED_TICKET_NOT_ASSIGNED

        # Finally, compare the two TLS Tickets
        if session1_tls_ticket != session2_tls_ticket:
            return TslSessionTicketSupportEnum.FAILED_TICKED_IGNORED

        return TslSessionTicketSupportEnum.SUCCEEDED


    @staticmethod
    def _extract_session_id(ssl_session):
        # type: (nassl._nassl.SSL_SESSION) -> Text
        """Extract the SSL session ID from a SSL session object or raises IndexError if the session ID was not set.
        """
        session_string = ((ssl_session.as_text()).split('Session-ID:'))[1]
        session_id = (session_string.split('Session-ID-ctx:'))[0].strip()
        return session_id


    @staticmethod
    def _extract_tls_session_ticket(ssl_session):
        # type: (nassl._nassl.SSL_SESSION) -> Text
        """Extract the TLS session ticket from a SSL session object or raises IndexError if the ticket was not set.
        """
        session_string = ((ssl_session.as_text()).split('TLS session ticket:'))[1]
        session_tls_ticket = (session_string.split('Compression:'))[0]
        return session_tls_ticket


    @staticmethod
    def _resume_ssl_session(server_info, ssl_session=None, should_enable_tls_ticket=False):
        # type: (ServerConnectivityInfo, Optional[nassl._nassl.SSL_SESSION], bool) -> nassl._nassl.SSL_SESSION
        """Connect to the server and returns the session object that was assigned for that connection.
        If ssl_session is given, tries to resume that session.
        """
        ssl_connection = server_info.get_preconfigured_ssl_connection()
        if not should_enable_tls_ticket:
            # Need to disable TLS tickets to test session IDs, according to rfc5077:
            # If a ticket is presented by the client, the server MUST NOT attempt
            # to use the Session ID in the ClientHello for stateful session resumption
            ssl_connection.ssl_client.disable_stateless_session_resumption()  # Turning off TLS tickets.

        if ssl_session:
            ssl_connection.ssl_client.set_session(ssl_session)

        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            new_session = ssl_connection.ssl_client.get_session()  # Get session data
        finally:
            ssl_connection.close()

        return new_session


class SessionResumptionRateScanResult(PluginScanResult):
    """The result of running SessionResumptionRateScanCommand on a specific server.

    Attributes:
        attempted_resumptions_nb (int): The total number of session ID resumptions that were attempted, which is 100.
        successful_resumptions_nb (int): The number of session ID resumptions that were successful.
        failed_resumptions_nb (int): The number of session ID resumptions that failed.
        errored_resumptions_list (Optional[List[(Text)]): A list of unexpected errors triggered while trying to perform
            session ID resumption with the server (should always be empty).
    """

    def __init__(
            self,
            server_info,                # type: ServerConnectivityInfo
            scan_command,               # type: SessionResumptionRateScanCommand
            attempted_resum_nb,         # type: int
            successful_resum_nb,        # type: int
            errored_resumptions_list    # type: List[Text]
    ):
        super(SessionResumptionRateScanResult, self).__init__(server_info, scan_command)
        self.attempted_resumptions_nb = attempted_resum_nb
        self.successful_resumptions_nb = successful_resum_nb
        self.errored_resumptions_list = errored_resumptions_list
        self.failed_resumptions_nb = attempted_resum_nb - successful_resum_nb - len(errored_resumptions_list)


    RESUMPTION_RESULT_FORMAT = '{4} ({0} successful, {1} failed, {2} errors, {3} total attempts).'
    RESUMPTION_LINE_FORMAT = '      {resumption_type:<35}{result}'
    RESUMPTION_ERROR_FORMAT = '        ERROR #{error_nb}: {error_msg}'

    def as_text(self):
        result_txt = [self._format_title(self.scan_command.get_title())]

        # Create the line which summarizes the session resumption rate
        if self.successful_resumptions_nb == self.attempted_resumptions_nb:
            resumption_supported_txt = 'OK - Supported'
        elif self.successful_resumptions_nb > 0:
            resumption_supported_txt = 'PARTIALLY SUPPORTED'
        elif self.failed_resumptions_nb == self.attempted_resumptions_nb:
            resumption_supported_txt = 'NOT SUPPORTED'
        else:
            resumption_supported_txt = 'ERROR'

        resum_rate_txt = self.RESUMPTION_RESULT_FORMAT.format(str(self.successful_resumptions_nb),
                                                              str(self.failed_resumptions_nb),
                                                              str(len(self.errored_resumptions_list)),
                                                              str(self.attempted_resumptions_nb),
                                                              resumption_supported_txt)
        result_txt.append(self.RESUMPTION_LINE_FORMAT.format(resumption_type='With Session IDs:',
                                                             result=resum_rate_txt))

        # Add error messages if there was any
        i = 0
        for error_msg in self.errored_resumptions_list:
            result_txt.append(self.RESUMPTION_ERROR_FORMAT.format(error_nb=i, error_msg=error_msg))
            i += 1

        return result_txt


    def as_xml(self):
        xml_result = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())

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



class SessionResumptionSupportScanResult(PluginScanResult):
    """The result of running SessionResumptionRateScanCommand on a specific server.

    Attributes:
        attempted_resumptions_nb (int): The total number of session ID resumptions that were attempted, which is 5.
        successful_resumptions_nb (int): The number of session ID resumptions that were successful.
        failed_resumptions_nb (int): The number of session ID resumptions that failed.
        errored_resumptions_list (Optional[List[(Text)]): A list of unexpected errors triggered while trying to perform
            session ID resumption with the server (should always be empty).
        is_ticket_resumption_supported (bool): True if the server honors client-initiated renegotiation attempts.
        ticket_resumption_failed_reason (Text): A message explaining why TLS ticket resumption failed.
        ticket_resumption_exception (Optional[Text]): An unexpected error that was raised while trying to perform ticket
            resumption (should never happen).
    """

    def __init__(
            self,
            server_info,                            # type: ServerConnectivityInfo
            scan_command,                           # type: SessionResumptionRateScanCommand
            attempted_resum_nb,                     # type: int
            successful_resum_nb,                    # type: int
            errored_resumptions_list,               # type: List[Text]
            is_ticket_resumption_supported,         # type: int
            ticket_resumption_failed_reason=None,   # type: Optional[Text]
            ticket_resumption_exception=None        # type: Optional[Exception]
    ):
        super(SessionResumptionSupportScanResult, self).__init__(server_info, scan_command)
        self.attempted_resumptions_nb = attempted_resum_nb
        self.successful_resumptions_nb = successful_resum_nb
        self.errored_resumptions_list = errored_resumptions_list
        self.failed_resumptions_nb = attempted_resum_nb - successful_resum_nb - len(errored_resumptions_list)

        self.is_ticket_resumption_supported = is_ticket_resumption_supported
        self.ticket_resumption_failed_reason = ticket_resumption_failed_reason

        # An exception was raised while trying to perform ticket resumption (should never happen)
        self.ticket_resumption_error = None
        if ticket_resumption_exception:
            self.ticket_resumption_error = '{} - {}'.format(str(ticket_resumption_exception.__class__.__name__),
                                                             str(ticket_resumption_exception))

        # We use a SessionResumptionRateScanResult to re-use code in as_text() and as_xml()
        self._rate_result = SessionResumptionRateScanResult(server_info, scan_command, attempted_resum_nb,
                                                            successful_resum_nb, errored_resumptions_list)

    RESUMPTION_LINE_FORMAT = '      {resumption_type:<35}{result}'

    def as_text(self):
        # Same output as --resum_rate but add a line about TLS ticket resumption at the end
        result_txt = self._rate_result.as_text()

        if self.ticket_resumption_error:
            ticket_txt = 'ERROR: {}'.format(self.ticket_resumption_error)
        else:
            ticket_txt = 'OK - Supported' \
                if self.is_ticket_resumption_supported \
                else 'NOT SUPPORTED - {}.'.format(self.ticket_resumption_failed_reason)


        result_txt.append(self.RESUMPTION_LINE_FORMAT.format(resumption_type='With TLS Tickets:', result=ticket_txt))
        return result_txt


    def as_xml(self):
        xml_result = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())

        # We keep the session resumption XML node
        resum_rate_xml = self._rate_result.as_xml()
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
