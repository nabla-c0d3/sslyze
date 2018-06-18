import socket
import struct
from abc import abstractmethod, ABC

from nassl.ssl_client import SslClient

from sslyze.utils.http_request_generator import HttpRequestGenerator
from sslyze.utils.http_response_parser import HttpResponseParser


class StartTlsError(IOError):
    """The server rejected the StartTLS negotiation.
    """
    pass


class TlsWrappedProtocolHelper(ABC):

    @abstractmethod
    def __init__(self, server_hostname: str) -> None:
        pass

    @abstractmethod
    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        """Send the right protocol-specific requests to prepare the server for the TLS handshake.
        """
        pass

    @abstractmethod
    def send_request(self, ssl_client: SslClient) -> str:
        """Send a protocol-specific "test" request to validate that the TLS handshake was successful.
        """
        pass


class TlsHelper(TlsWrappedProtocolHelper):
    """Do not do anything.
    """

    def __init__(self, server_hostname: str) -> None:
        pass

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        pass

    def send_request(self, ssl_client: SslClient) -> str:
        return ''


class HttpsHelper(TlsWrappedProtocolHelper):

    GET_RESULT_FORMAT = 'HTTP {0} {1}{2}'

    ERR_HTTP_TIMEOUT = 'Timeout on HTTP GET'
    ERR_NOT_HTTP = 'Server response was not HTTP'
    ERR_GENERIC = 'Error sending HTTP GET'

    def __init__(self, server_hostname: str) -> None:
        self._hostname = server_hostname

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        # Nothing to do here
        pass

    def send_request(self, ssl_client: SslClient) -> str:
        """Send an HTTP GET to the server and return the HTTP status code.
        """
        try:
            ssl_client.write(HttpRequestGenerator.get_request(self._hostname))

            # Parse the response and print the Location header
            http_response = HttpResponseParser.parse_from_ssl_connection(ssl_client)
            if http_response.version == 9:
                # HTTP 0.9 => Probably not an HTTP response
                result = self.ERR_NOT_HTTP
            else:
                redirect = ''
                if 300 <= http_response.status < 400:
                    redirect_location = http_response.getheader('Location')
                    if redirect_location:
                        # Add redirection URL to the result
                        redirect = f' - {redirect_location}'

                result = self.GET_RESULT_FORMAT.format(http_response.status, http_response.reason, redirect)
        except socket.timeout:
            result = self.ERR_HTTP_TIMEOUT
        except IOError:
            result = self.ERR_GENERIC

        return result


class SmtpHelper(TlsWrappedProtocolHelper):
    """Perform an SMTP StartTLS negotiation.
    """

    ERR_SMTP_REJECTED = 'SMTP EHLO was rejected'
    ERR_NO_SMTP_STARTTLS = 'SMTP STARTTLS not supported'

    def __init__(self, server_hostname: str) -> None:
        pass

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        # Get the SMTP banner
        sock.recv(2048)

        # Send a EHLO and wait for the 250 status
        sock.send(b'EHLO sslyze.scan\r\n')
        if b'250 ' not in sock.recv(2048):
            raise StartTlsError(self.ERR_SMTP_REJECTED)

        # Send a STARTTLS
        sock.send(b'STARTTLS\r\n')
        if b'220' not in sock.recv(2048):
            raise StartTlsError(self.ERR_NO_SMTP_STARTTLS)

    def send_request(self, ssl_client: SslClient) -> str:
        try:
            ssl_client.write(b'NOOP\r\n')
            result = ssl_client.read(2048).strip().decode('utf-8')
        except socket.timeout:
            result = 'Timeout on SMTP NOOP'
        return result


class XmppHelper(TlsWrappedProtocolHelper):
    """Perform an XMPP StartTLS negotiation.
    """

    ERR_XMPP_REJECTED = 'Error opening XMPP stream, try --xmpp_to'
    ERR_XMPP_HOST_UNKNOWN = 'Error opening XMPP stream: server returned host-unknown error, try --xmpp_to'
    ERR_XMPP_NO_STARTTLS = 'XMPP STARTTLS not supported'

    XMPP_OPEN_STREAM = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' " \
                       "xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='{xmpp_to}' xml:lang='en' version='1.0'>"
    XMPP_STARTTLS = b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"

    def __init__(self, server_hostname: str) -> None:
        self._xmpp_to = server_hostname

    def override_xmpp_to(self, xmpp_to: str) -> None:
        self._xmpp_to = xmpp_to

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        # Open an XMPP stream
        sock.send(self.XMPP_OPEN_STREAM.format(xmpp_to=self._xmpp_to).encode('utf-8'))

        # Get the server's features and check for an error
        server_resp = sock.recv(4096)
        if b'<stream:error>' in server_resp:
            raise StartTlsError(self.ERR_XMPP_REJECTED)
        elif b'</stream:features>' not in server_resp:
            # Get all the server features before initiating startTLS
            sock.recv(4096)

        # Send a STARTTLS message
        sock.send(self.XMPP_STARTTLS)
        xmpp_resp = sock.recv(2048)

        if b'host-unknown' in xmpp_resp:
            raise StartTlsError(self.ERR_XMPP_HOST_UNKNOWN)

        if b'proceed' not in xmpp_resp:
            raise StartTlsError(self.ERR_XMPP_NO_STARTTLS)

    def send_request(self, ssl_client: SslClient) -> str:
        # Not implemented
        return ''


class XmppServerHelper(XmppHelper):
    XMPP_OPEN_STREAM = "<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' " \
                       "xmlns:tls='http://www.ietf.org/rfc/rfc2595.txt' to='{xmpp_to}' xml:lang='en' version='1.0'>"


class LdapHelper(TlsWrappedProtocolHelper):
    """Performs an LDAP StartTLS negotiation.
    """

    ERR_NO_STARTTLS = 'LDAP AUTH TLS was rejected'

    START_TLS_CMD = b'0\x1d\x02\x01\x01w\x18\x80\x161.3.6.1.4.1.1466.20037'
    START_TLS_OK = b'\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04'
    START_TLS_OK2 = b'Start TLS request accepted'
    START_TLS_OK_APACHEDS = b'\x30\x26\x02\x01\x01\x78\x21\x0a\x01\x00\x04\x00\x04\x00\x8a\x16\x31\x2e\x33\x2e\x36' \
                            b'\x2e\x31\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x2e\x32\x30\x30\x33\x37\x8b\x00'

    def __init__(self, server_hostname: str) -> None:
        pass

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        sock.send(self.START_TLS_CMD)
        data = sock.recv(2048)
        if self.START_TLS_OK not in data and self.START_TLS_OK_APACHEDS not in data and self.START_TLS_OK2 not in data:
            raise StartTlsError(self.ERR_NO_STARTTLS + ', returned: "' + repr(data) + '"')

    def send_request(self, ssl_client: SslClient) -> str:
        # Not implemented
        return ''


class RdpHelper(TlsWrappedProtocolHelper):
    """Perform an RDP StartTLS negotiation.
    """

    ERR_NO_STARTTLS = 'RDP AUTH TLS was rejected'

    START_TLS_CMD = b'\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
    START_TLS_OK = b'Start TLS request accepted.'

    def __init__(self, server_hostname: str) -> None:
        pass

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        sock.send(self.START_TLS_CMD)
        data = sock.recv(4)
        if not data or len(data) != 4 or data[:2] != b'\x03\x00':
            raise StartTlsError(self.ERR_NO_STARTTLS)
        packet_len = struct.unpack(">H", data[2:])[0] - 4
        data = sock.recv(packet_len)

        if not data or len(data) != packet_len:
            raise StartTlsError(self.ERR_NO_STARTTLS)

    def send_request(self, ssl_client: SslClient) -> str:
        # Not implemented
        return ''


class GenericStartTlsHelper(TlsWrappedProtocolHelper, ABC):
    """Perform a StartTLS negotiation.
    """

    # To be defined in subclasses
    ERR_NO_STARTTLS = b''
    START_TLS_CMD = b''
    START_TLS_OK = b''
    SHOULD_WAIT_FOR_SERVER_BANNER = True

    def __init__(self, server_hostname: str) -> None:
        pass

    def prepare_socket_for_tls_handshake(self, sock: socket.socket) -> None:
        # Grab the banner
        if self.SHOULD_WAIT_FOR_SERVER_BANNER:
            sock.recv(2048)

        # Send Start TLS
        sock.send(self.START_TLS_CMD)
        if self.START_TLS_OK not in sock.recv(2048):
            raise StartTlsError(self.ERR_NO_STARTTLS)

    def send_request(self, ssl_client: SslClient) -> str:
        # Not implemented
        return ''


class ImapHelper(GenericStartTlsHelper):

    ERR_NO_STARTTLS = b'IMAP START TLS was rejected'

    START_TLS_CMD = b'. STARTTLS\r\n'
    START_TLS_OK = b'. OK'


class Pop3Helper(GenericStartTlsHelper):

    ERR_NO_STARTTLS = b'POP START TLS was rejected'

    START_TLS_CMD = b'STLS\r\n'
    START_TLS_OK = b'+OK'


class FtpHelper(GenericStartTlsHelper):

    ERR_NO_STARTTLS = b'FTP AUTH TLS was rejected'

    START_TLS_CMD = b'AUTH TLS\r\n'
    START_TLS_OK = b'234'


class PostgresHelper(GenericStartTlsHelper):

    ERR_NO_STARTTLS = b'Postgres AUTH TLS was rejected'

    START_TLS_CMD = b'\x00\x00\x00\x08\x04\xD2\x16\x2F'
    START_TLS_OK = b'S'
    SHOULD_WAIT_FOR_SERVER_BANNER = False
