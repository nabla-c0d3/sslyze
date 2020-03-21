from enum import Enum
from typing import Optional, Tuple

import nassl

from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


class _ScanJobResultEnum(Enum):
    TLS_TICKET_RESUMPTION = 1
    SESSION_ID_RESUMPTION = 2


def resume_tls_session(
    server_info: ServerConnectivityInfo,
    tls_version_to_use: TlsVersionEnum,
    tls_session: Optional[nassl._nassl.SSL_SESSION] = None,
    should_enable_tls_ticket: bool = False,
) -> nassl._nassl.SSL_SESSION:
    """Connect to the server and returns the session object that was assigned for that connection.
    If ssl_session is given, tries to resume that session.
    """
    ssl_connection = server_info.get_preconfigured_tls_connection(override_tls_version=tls_version_to_use)
    if not should_enable_tls_ticket:
        # Need to disable TLS tickets to test session IDs, according to rfc5077:
        # If a ticket is presented by the client, the server MUST NOT attempt
        # to use the Session ID in the ClientHello for stateful session resumption
        ssl_connection.ssl_client.disable_stateless_session_resumption()  # Turning off TLS tickets.

    if tls_session:
        ssl_connection.ssl_client.set_session(tls_session)

    try:
        # Perform the SSL handshake
        ssl_connection.connect()
        new_session = ssl_connection.ssl_client.get_session()  # Get session data
    finally:
        ssl_connection.close()

    return new_session


def _extract_session_id(ssl_session: nassl._nassl.SSL_SESSION) -> str:
    """Extract the SSL session ID from a SSL session object or raises IndexError if the session ID was not set.
    """
    session_string = ((ssl_session.as_text()).split("Session-ID:"))[1]
    session_id = (session_string.split("Session-ID-ctx:"))[0].strip()
    return session_id


def resume_with_session_id(
    server_info: ServerConnectivityInfo, tls_version_to_use: TlsVersionEnum
) -> Tuple[_ScanJobResultEnum, bool]:
    """Perform one session resumption using Session IDs.
    """
    session1 = resume_tls_session(server_info, tls_version_to_use)
    try:
        # Recover the session ID
        session1_id = _extract_session_id(session1)
    except IndexError:
        # Session ID not assigned
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, False

    if session1_id == "":
        # Session ID empty
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, False

    # Try to resume that SSL session
    session2 = resume_tls_session(server_info, tls_version_to_use, session1)
    try:
        # Recover the session ID
        session2_id = _extract_session_id(session2)
    except IndexError:
        # Session ID not assigned
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, False

    # Finally, compare the two Session IDs
    if session1_id != session2_id:
        # Session ID assigned but not accepted
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, False

    return _ScanJobResultEnum.SESSION_ID_RESUMPTION, True
