from typing import Tuple

import nassl

from sslyze.plugins.session_resumption._resumption_with_id import retrieve_tls_session, _ScanJobResultEnum
from sslyze.server_connectivity import ServerConnectivityInfo


def resume_with_tls_ticket(
    server_info: ServerConnectivityInfo,
) -> Tuple[_ScanJobResultEnum, bool]:
    """Perform one session resumption using TLS Session Tickets."""
    # Connect to the server and keep the TLS session
    session1 = retrieve_tls_session(server_info, should_enable_tls_ticket=True)
    try:
        # Recover the TLS ticket
        session1_tls_ticket = _extract_tls_session_ticket(session1)
    except IndexError:
        # Ticket was not assigned
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, False

    # Try to resume that session using the TLS ticket
    session2 = retrieve_tls_session(server_info, session_to_resume=session1, should_enable_tls_ticket=True)
    try:
        # Recover the TLS ticket
        session2_tls_ticket = _extract_tls_session_ticket(session2)
    except IndexError:
        # Ticket was not assigned
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, False

    # Finally, compare the two TLS Tickets
    if session1_tls_ticket != session2_tls_ticket:
        # The Ticket we supplied got ignored
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, False

    return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, True


def _extract_tls_session_ticket(ssl_session: nassl._nassl.SSL_SESSION) -> str:
    """Extract the TLS session ticket from a SSL session object or raises IndexError if the ticket was not set."""
    session_string = ((ssl_session.as_text()).split("TLS session ticket:"))[1]
    session_tls_ticket = (session_string.split("Compression:"))[0]
    return session_tls_ticket
