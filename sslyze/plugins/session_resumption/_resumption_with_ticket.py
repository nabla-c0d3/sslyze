from enum import Enum, unique
from typing import Tuple

import nassl

from sslyze.plugins.session_resumption._resumption_with_id import retrieve_tls_session, _ScanJobResultEnum
from sslyze.server_connectivity import ServerConnectivityInfo


@unique
class TlsSessionTicketSupportEnum(Enum):
    """The result of attempting to resume a TLS session with the server using TLS Tickets.
    """

    SUCCEEDED = 1
    FAILED_TICKET_NOT_ASSIGNED = 2
    FAILED_TICKED_IGNORED = 3
    FAILED_ONLY_TLS_1_3_SUPPORTED = 4

    # TODO(AD): Switch to these names for v5.0.0 and leverage ServerOnlySupportsTls13() to simplify flow
    # SUPPORTED = 1
    # NOT_SUPPORTED_TICKET_NOT_ASSIGNED = 2
    # NOT_SUPPORTED_TICKET_IGNORED = 3
    # SERVER_IS_TLS_1_3_ONLY = 4


def resume_with_tls_ticket(
    server_info: ServerConnectivityInfo,
) -> Tuple[_ScanJobResultEnum, TlsSessionTicketSupportEnum]:
    """Perform one session resumption using TLS Session Tickets.
    """
    # Connect to the server and keep the TLS session
    session1 = retrieve_tls_session(server_info, should_enable_tls_ticket=True)
    try:
        # Recover the TLS ticket
        session1_tls_ticket = _extract_tls_session_ticket(session1)
    except IndexError:
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, TlsSessionTicketSupportEnum.FAILED_TICKET_NOT_ASSIGNED

    # Try to resume that session using the TLS ticket
    session2 = retrieve_tls_session(server_info, session_to_resume=session1, should_enable_tls_ticket=True)
    try:
        # Recover the TLS ticket
        session2_tls_ticket = _extract_tls_session_ticket(session2)
    except IndexError:
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, TlsSessionTicketSupportEnum.FAILED_TICKET_NOT_ASSIGNED

    # Finally, compare the two TLS Tickets
    if session1_tls_ticket != session2_tls_ticket:
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, TlsSessionTicketSupportEnum.FAILED_TICKED_IGNORED

    return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, TlsSessionTicketSupportEnum.SUCCEEDED


def _extract_tls_session_ticket(ssl_session: nassl._nassl.SSL_SESSION) -> str:
    """Extract the TLS session ticket from a SSL session object or raises IndexError if the ticket was not set.
    """
    session_string = ((ssl_session.as_text()).split("TLS session ticket:"))[1]
    session_tls_ticket = (session_string.split("Compression:"))[0]
    return session_tls_ticket
