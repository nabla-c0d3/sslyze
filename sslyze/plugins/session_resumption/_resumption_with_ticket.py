from enum import Enum, unique
from typing import Tuple

import nassl

from sslyze.plugins.session_resumption._resumption_with_id import resume_tls_session, _ScanJobResultEnum
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum
from sslyze.errors import ServerRejectedTlsHandshake


@unique
class TslSessionTicketSupportEnum(Enum):
    SUCCEEDED = 1
    FAILED_TICKET_NOT_ASSIGNED = 2
    FAILED_TICKED_IGNORED = 3
    FAILED_ONLY_TLS_1_3_SUPPORTED = 4


def resume_with_tls_ticket(
    server_info: ServerConnectivityInfo, tls_version_to_use: TlsVersionEnum
) -> Tuple[_ScanJobResultEnum, TslSessionTicketSupportEnum]:
    """Perform one session resumption using TLS Session Tickets.
    """
    # Connect to the server and keep the SSL session
    try:
        session1 = resume_tls_session(server_info, tls_version_to_use, should_enable_tls_ticket=True)
    except ServerRejectedTlsHandshake:
        if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
            return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, TslSessionTicketSupportEnum.FAILED_ONLY_TLS_1_3_SUPPORTED
        else:
            raise

    try:
        # Recover the TLS ticket
        session1_tls_ticket = _extract_tls_session_ticket(session1)
    except IndexError:
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, TslSessionTicketSupportEnum.FAILED_TICKET_NOT_ASSIGNED

    # Try to resume that session using the TLS ticket
    session2 = resume_tls_session(server_info, tls_version_to_use, session1, should_enable_tls_ticket=True)
    try:
        # Recover the TLS ticket
        session2_tls_ticket = _extract_tls_session_ticket(session2)
    except IndexError:
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, TslSessionTicketSupportEnum.FAILED_TICKET_NOT_ASSIGNED

    # Finally, compare the two TLS Tickets
    if session1_tls_ticket != session2_tls_ticket:
        return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, TslSessionTicketSupportEnum.FAILED_TICKED_IGNORED

    return _ScanJobResultEnum.TLS_TICKET_RESUMPTION, TslSessionTicketSupportEnum.SUCCEEDED


def _extract_tls_session_ticket(ssl_session: nassl._nassl.SSL_SESSION) -> str:
    """Extract the TLS session ticket from a SSL session object or raises IndexError if the ticket was not set.
    """
    session_string = ((ssl_session.as_text()).split("TLS session ticket:"))[1]
    session_tls_ticket = (session_string.split("Compression:"))[0]
    return session_tls_ticket
