from enum import Enum
from typing import Optional, Tuple

import nassl

from sslyze.errors import ServerRejectedTlsHandshake
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


class TlsResumptionSupportEnum(str, Enum):
    """The result of attempting to resume TLS sessions with the server.

    Attributes:
        FULLY_SUPPORTED: All the session resumption attempts were successful.
        PARTIALLY_SUPPORTED: Only some of the session resumption attempts were successful.
        NOT_SUPPORTED: None of the session resumption attempts were successful.
        SERVER_IS_TLS_1_3_ONLY: The server only supports TLS 1.3, which does not support Session ID nor TLS Tickets
            resumption.
    """

    FULLY_SUPPORTED = "FULLY_SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    SERVER_IS_TLS_1_3_ONLY = "SERVER_IS_TLS_1_3_ONLY"


class _ScanJobResultEnum(Enum):
    TLS_TICKET_RESUMPTION = 1
    SESSION_ID_RESUMPTION = 2


class ServerOnlySupportsTls13(Exception):
    """If the server only supports TLS 1.3 or higher, it does not support session resumption with IDs or tickets."""

    pass


def retrieve_tls_session(
    server_info: ServerConnectivityInfo,
    session_to_resume: Optional[nassl._nassl.SSL_SESSION] = None,
    should_enable_tls_ticket: bool = False,
) -> nassl._nassl.SSL_SESSION:
    """Connect to the server and returns the session object that was assigned for that connection.

    If ssl_session is given, tries to resume that session.
    """
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as there is no session resumption (with IDs or
    # tickets) with TLS 1.3
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        tls_version_to_use = TlsVersionEnum.TLS_1_2
        downgraded_from_tls_1_3 = True
    else:
        tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported
        downgraded_from_tls_1_3 = False

    ssl_connection = server_info.get_preconfigured_tls_connection(override_tls_version=tls_version_to_use)
    if not should_enable_tls_ticket:
        # Need to disable TLS tickets to test session IDs, according to rfc5077:
        # If a ticket is presented by the client, the server MUST NOT attempt
        # to use the Session ID in the ClientHello for stateful session resumption
        ssl_connection.ssl_client.disable_stateless_session_resumption()  # Turning off TLS tickets.

    if session_to_resume:
        ssl_connection.ssl_client.set_session(session_to_resume)

    try:
        # Perform the TLS handshake
        ssl_connection.connect()
        new_session = ssl_connection.ssl_client.get_session()  # Get session data

    except ServerRejectedTlsHandshake:
        if downgraded_from_tls_1_3:
            raise ServerOnlySupportsTls13()
        else:
            raise

    finally:
        ssl_connection.close()

    return new_session


def _extract_session_id(ssl_session: nassl._nassl.SSL_SESSION) -> str:
    """Extract the SSL session ID from a SSL session object or raises IndexError if the session ID was not set."""
    session_string = ((ssl_session.as_text()).split("Session-ID:"))[1]
    session_id = (session_string.split("Session-ID-ctx:"))[0].strip()
    return session_id


def resume_with_session_id(server_info: ServerConnectivityInfo) -> Tuple[_ScanJobResultEnum, bool]:
    """Perform one session resumption using Session IDs."""
    # Create a new TLS session with the server
    session1 = retrieve_tls_session(server_info)
    try:
        # Recover the session ID
        session1_id = _extract_session_id(session1)
    except IndexError:
        # Session ID not assigned
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, False

    if session1_id == "":
        # Session ID empty
        return _ScanJobResultEnum.SESSION_ID_RESUMPTION, False

    # Try to resume that TLS session
    session2 = retrieve_tls_session(server_info, session_to_resume=session1)
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
