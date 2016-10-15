# -*- coding: utf-8 -*-
"""Main classes for performing all the SSL connections within the plugins.
"""

import random
import socket
import struct
import time
from base64 import b64encode
from urllib import quote

from nassl import _nassl, SSL_VERIFY_NONE
from nassl.debug_ssl_client import DebugSslClient
from nassl.ssl_client import ClientCertificateRequested
from sslyze.utils.http_request_generator import HttpRequestGenerator

from sslyze.utils.http_response_parser import HttpResponseParser


class SSLHandshakeRejected(IOError):
    """The server explicitly rejected the SSL handshake.
    """
    pass



class StartTLSError(IOError):
    """The server rejected the StartTLS negotiation.
    """
    pass



class ProxyError(IOError):
    """The proxy was offline or did not return HTTP 200 to our CONNECT request.
    """
    pass



class SSLConnection(DebugSslClient):
    """Base SSL connection class.
    """

    # The following errors mean that the server explicitly rejected the handshake. The goal to differentiate rejected
    # handshakes from random network errors such as the server going offline, etc.
    HANDSHAKE_REJECTED_SOCKET_ERRORS = {'was forcibly closed': 'Received FIN',
                                        'reset by peer': 'Received RST'}

    HANDSHAKE_REJECTED_SSL_ERRORS = {'sslv3 alert handshake failure': 'Alert handshake failure',
                                     'no ciphers available': 'No ciphers available',
                                     'excessive message size': 'Excessive message size',
                                     'bad mac decode': 'Bad mac decode',
                                     'wrong version number': 'Wrong version number',
                                     'no cipher match': 'No cipher match',
                                     'bad decompression': 'Bad decompression',
                                     'peer error no cipher': 'Peer error no cipher',
                                     'no cipher list': 'No ciphers list',
                                     'insufficient security': 'Insufficient security',
                                     'block type is not 01': 'block type is not 01',  # Actually an RSA error
                                     'tlsv1 alert protocol version': 'Alert: protocol version '}

    # Constants for tunneling the traffic through a proxy
    HTTP_CONNECT_REQ = 'CONNECT {0}:{1} HTTP/1.1\r\n\r\n'
    HTTP_CONNECT_REQ_PROXY_AUTH_BASIC = 'CONNECT {0}:{1} HTTP/1.1\r\nProxy-Authorization: Basic {2}\r\n\r\n'

    # Errors caused by the proxy
    ERR_CONNECT_REJECTED = 'The proxy rejected the CONNECT request for this host'
    ERR_PROXY_OFFLINE = 'Could not connect to the proxy: "{0}"'

    # Restrict cipher list to make the client hello smaller so we don't run into
    # https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=665452
    DEFAULT_SSL_CIPHER_LIST = 'HIGH:MEDIUM:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA'

    # Default socket settings global to all SSLyze connections; can be overridden
    NETWORK_MAX_RETRIES = 3
    NETWORK_TIMEOUT = 5

    @classmethod
    def set_global_network_settings(cls, network_max_retries, network_timeout):
        cls.NETWORK_MAX_RETRIES = network_max_retries
        cls.NETWORK_TIMEOUT = network_timeout


    def __init__(self, host, ip, port, ssl_version, ssl_verify_locations=None, client_auth_creds=None,
                 should_ignore_client_auth=False):
        if client_auth_creds:
            # A client certificate and private key were provided
            super(SSLConnection, self).__init__(ssl_version=ssl_version,
                                                ssl_verify=SSL_VERIFY_NONE,
                                                ssl_verify_locations=ssl_verify_locations,
                                                client_certchain_file=client_auth_creds.client_certificate_chain_path,
                                                client_key_file=client_auth_creds.client_key_path,
                                                client_key_type=client_auth_creds.client_key_type,
                                                client_key_password=client_auth_creds.client_key_password,
                                                ignore_client_authentication_requests=False)
        else:
            # No client cert and key
            super(SSLConnection, self).__init__(ssl_version=ssl_version,
                                                ssl_verify=SSL_VERIFY_NONE,
                                                ssl_verify_locations=ssl_verify_locations,
                                                ignore_client_authentication_requests=should_ignore_client_auth)

        self._sock = None
        self._host = host
        self._ip = ip
        self._port = port
        self._tunnel_host = None
        self.set_cipher_list(self.DEFAULT_SSL_CIPHER_LIST)


    def enable_http_connect_tunneling(self, tunnel_host, tunnel_port, tunnel_user=None, tunnel_password=None):
        """Proxy the traffic through an HTTP Connect proxy."""
        self._tunnel_host = tunnel_host
        self._tunnel_port = tunnel_port
        self._tunnel_basic_auth_token = None
        if tunnel_user is not None:
            self._tunnel_basic_auth_token = b64encode('{0}:{1}'.format(quote(tunnel_user), quote(tunnel_password)))


    def do_pre_handshake(self, network_timeout):
        """Open a socket to the server; setup HTTP tunneling if a proxy was configured.
        """
        if self._tunnel_host:
            # Proxy configured; setup HTTP tunneling
            try:
                self._sock = socket.create_connection((self._tunnel_host, self._tunnel_port), network_timeout)
            except socket.timeout as e:
                raise ProxyError(self.ERR_PROXY_OFFLINE.format(e[0]))
            except socket.error as e:
                raise ProxyError(self.ERR_PROXY_OFFLINE.format(e[1]))

            # Send a CONNECT request with the host we want to tunnel to
            if self._tunnel_basic_auth_token is None:
                self._sock.send(self.HTTP_CONNECT_REQ.format(self._host, self._port))
            else:
                self._sock.send(self.HTTP_CONNECT_REQ_PROXY_AUTH_BASIC.format(self._host, self._port,
                                                                              self._tunnel_basic_auth_token))
            http_response = parse_http_response(self._sock)

            # Check if the proxy was able to connect to the host
            if http_response.status != 200:
                raise ProxyError(self.ERR_CONNECT_REJECTED)
        else:
            # No proxy; connect directly to the server
            self._sock = socket.create_connection((self._ip, self._port), network_timeout)


    def connect(self, network_timeout=None, network_max_retries=None):
        final_timeout = self.NETWORK_TIMEOUT if network_timeout is None else network_timeout
        final_max_retries = self.NETWORK_MAX_RETRIES if network_max_retries is None else network_max_retries
        retry_attempts = 0
        delay = 0
        while True:
            try:
                # Sleep if it's a retry attempt
                time.sleep(delay)

                # StartTLS negotiation or proxy setup if needed
                self.do_pre_handshake(final_timeout)

                try: # SSL handshake
                    self.do_handshake()

                # The goal here to differentiate rejected SSL handshakes (which will
                # raise SSLHandshakeRejected) from random network errors
                except socket.error as e:
                    for error_msg in self.HANDSHAKE_REJECTED_SOCKET_ERRORS.keys():
                        if error_msg in str(e.args):
                            raise SSLHandshakeRejected('TCP / ' + self.HANDSHAKE_REJECTED_SOCKET_ERRORS[error_msg])
                    raise # Unknown socket error
                except IOError as e:
                    if 'Nassl SSL handshake failed' in str(e.args):
                        raise SSLHandshakeRejected('TLS / Unexpected EOF')
                    raise
                except _nassl.OpenSSLError as e:
                    for error_msg in self.HANDSHAKE_REJECTED_SSL_ERRORS.keys():
                        if error_msg in str(e.args):
                            raise SSLHandshakeRejected('TLS / ' + self.HANDSHAKE_REJECTED_SSL_ERRORS[error_msg])
                    raise # Unknown SSL error if we get there
                except ClientCertificateRequested:
                    # Server expected a client certificate and we didn't provide one
                    raise

            # Pass on exceptions for rejected handshakes
            except SSLHandshakeRejected:
                raise
            except ClientCertificateRequested:
                raise

            except _nassl.OpenSSLError:
                # Raise unknown OpenSSL errors
                raise

            # Attempt to retry connection if a network error occurred
            except:
                retry_attempts += 1
                if retry_attempts >= final_max_retries:
                    # Exhausted the number of retry attempts, give up
                    raise
                elif retry_attempts == 1:
                    delay = random.random()
                else: # Exponential back off
                    delay = min(6, 2*delay) # Cap max delay at 6 seconds

            else: # No network error occurred
                break


    def close(self):
        self.shutdown()
        if self._sock:
            self._sock.close()


    def post_handshake_check(self):
        return ''


class HTTPSConnection(SSLConnection):
    """SSL connection class that sends an HTTP GET request after the SSL handshake.
    """

    GET_RESULT_FORMAT = 'HTTP {0} {1}{2}'

    ERR_HTTP_TIMEOUT = 'Timeout on HTTP GET'
    ERR_NOT_HTTP = 'Server response was not HTTP'
    ERR_GENERIC = 'Error sending HTTP GET'


    def post_handshake_check(self):

        try:
            # TODO: This is code only used by OpenSSLCipherSuitesPlugin anf should be moved there
            # Send an HTTP GET to the server and store the HTTP Status Code
            self.write(HttpRequestGenerator.get_request(self._host))

            # Parse the response and print the Location header
            http_response = HttpResponseParser.parse(self)
            if http_response.version == 9 :
                # HTTP 0.9 => Probably not an HTTP response
                result = self.ERR_NOT_HTTP
            else:
                redirect = ''
                if 300 <= http_response.status < 400:
                    if http_response.getheader('Location', None):
                        # Add redirection URL to the result
                        redirect = ' - ' + http_response.getheader('Location', None)

                result = self.GET_RESULT_FORMAT.format(http_response.status, http_response.reason, redirect)
        except socket.timeout:
            result = self.ERR_HTTP_TIMEOUT
        except IOError:
            result = self.ERR_GENERIC

        return result


class SMTPConnection(SSLConnection):
    """SSL connection class that performs an SMTP StartTLS negotiation before the SSL handshake and sends a NOOP after
    the handshake.
    """

    ERR_SMTP_REJECTED = 'SMTP EHLO was rejected'
    ERR_NO_SMTP_STARTTLS = 'SMTP STARTTLS not supported'


    def do_pre_handshake(self, network_timeout):
        super(SMTPConnection, self).do_pre_handshake(network_timeout)

        # Get the SMTP banner
        self._sock.recv(2048)

        # Send a EHLO and wait for the 250 status
        self._sock.send('EHLO sslyze.scan\r\n')
        if '250 ' not in self._sock.recv(2048):
            raise StartTLSError(self.ERR_SMTP_REJECTED)

        # Send a STARTTLS
        self._sock.send('STARTTLS\r\n')
        if '220'  not in self._sock.recv(2048):
            raise StartTLSError(self.ERR_NO_SMTP_STARTTLS)


    def post_handshake_check(self):
        try:
            self.write('NOOP\r\n')
            result = self.read(2048).strip()
        except socket.timeout:
            result = 'Timeout on SMTP NOOP'
        return result



class XMPPConnection(SSLConnection):
    """SSL connection class that performs an XMPP StartTLS negotiation before the SSL handshake.
    """

    ERR_XMPP_REJECTED = 'Error opening XMPP stream, try --xmpp_to'
    ERR_XMPP_HOST_UNKNOWN = 'Error opening XMPP stream: server returned host-unknown error, try --xmpp_to'
    ERR_XMPP_NO_STARTTLS = 'XMPP STARTTLS not supported'

    XMPP_OPEN_STREAM = ("<stream:stream xmlns='jabber:client' xmlns:stream='"
        "http://etherx.jabber.org/streams' xmlns:tls='http://www.ietf.org/rfc/"
        "rfc2595.txt' to='{0}' xml:lang='en' version='1.0'>" )
    XMPP_STARTTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"


    def __init__(self, host, ip, port, ssl_version, ssl_verify_locations=None, client_auth_creds=None,
                 should_ignore_client_auth=False):
        super(XMPPConnection, self).__init__(host, ip, port, ssl_version, ssl_verify_locations, client_auth_creds,
                                             should_ignore_client_auth)
        self._xmpp_to = host


    def set_xmpp_to(self, xmpp_to):
        """XMPP host specified with the XMPP handshake."""
        self._xmpp_to = xmpp_to


    def do_pre_handshake(self, network_timeout):
        """Connect to a host on a given (SSL) port, send a STARTTLS command, and perform the SSL handshake.
        """
        super(XMPPConnection, self).do_pre_handshake(network_timeout)

        # Open an XMPP stream
        self._sock.send(self.XMPP_OPEN_STREAM.format(self._xmpp_to))

        # Get the server's features and check for an error
        serverResp = self._sock.recv(4096)
        if '<stream:error>' in serverResp:
            raise StartTLSError(self.ERR_XMPP_REJECTED)
        elif '</stream:features>' not in serverResp:
            # Get all the server features before initiating startTLS
            self._sock.recv(4096)

        # Send a STARTTLS message
        self._sock.send(self.XMPP_STARTTLS)
        xmpp_resp = self._sock.recv(2048)

        if 'host-unknown' in xmpp_resp:
            raise StartTLSError(self.ERR_XMPP_HOST_UNKNOWN)

        if 'proceed' not in xmpp_resp:
            raise StartTLSError(self.ERR_XMPP_NO_STARTTLS)


class XMPPServerConnection(XMPPConnection):
    XMPP_OPEN_STREAM = ("<stream:stream xmlns='jabber:server' xmlns:stream='"
        "http://etherx.jabber.org/streams' xmlns:tls='http://www.ietf.org/rfc/"
        "rfc2595.txt' to='{0}' xml:lang='en' version='1.0'>" )


class LDAPConnection(SSLConnection):
    """SSL connection class that performs an LDAP StartTLS negotiation before the SSL handshake.
    """

    ERR_NO_STARTTLS = 'LDAP AUTH TLS was rejected'

    START_TLS_CMD = bytearray(b'0\x1d\x02\x01\x01w\x18\x80\x161.3.6.1.4.1.1466.20037')
    START_TLS_OK = '\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x00\x04\x00\x04'
    START_TLS_OK2 = 'Start TLS request accepted'
    START_TLS_OK_APACHEDS = '\x30\x26\x02\x01\x01\x78\x21\x0a\x01\x00\x04\x00\x04\x00\x8a\x16\x31\x2e\x33\x2e\x36\x2e\x31\x2e\x34\x2e\x31\x2e\x31\x34\x36\x36\x2e\x32\x30\x30\x33\x37\x8b\x00'


    def do_pre_handshake(self, network_timeout):
        """Connect to a host on a given (SSL) port, send a STARTTLS command, and perform the SSL handshake.
        """
        super(LDAPConnection, self).do_pre_handshake(network_timeout)

        # Send Start TLS
        self._sock.send(self.START_TLS_CMD)
        data = self._sock.recv(2048)
        if self.START_TLS_OK not in data and self.START_TLS_OK_APACHEDS not in data and self.START_TLS_OK2 not in data:
            raise StartTLSError(self.ERR_NO_STARTTLS + ', returned: "' + data + '" (hex: "' + data.encode('hex') + '")')


class RDPConnection(SSLConnection):
    """SSL connection class that performs an RDP StartTLS negotiation before the SSL handshake.
    """

    ERR_NO_STARTTLS = 'RDP AUTH TLS was rejected'

    START_TLS_CMD = bytearray(b'\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00')
    START_TLS_OK = 'Start TLS request accepted.'

    def do_pre_handshake(self, network_timeout):
        """
        Connect to a host on a given (SSL) port, send a STARTTLS command,
        and perform the SSL handshake.
        """
        super(RDPConnection, self).do_pre_handshake(network_timeout)

        self._sock.send(self.START_TLS_CMD)
        data = self._sock.recv(4)
        if not data or len(data) != 4 or data[:2] != '\x03\x00' :
            raise StartTLSError(self.ERR_NO_STARTTLS)
        packet_len = struct.unpack(">H", data[2:])[0] - 4
        data = self._sock.recv(packet_len)

        if not data or len(data) != packet_len :
            raise StartTLSError(self.ERR_NO_STARTTLS)



class GenericStartTLSConnection(SSLConnection):
    """SSL connection class that performs a StartTLS negotiation before the SSL handshake.
    """

    # To be defined in subclasses
    ERR_NO_STARTTLS = ''
    START_TLS_CMD = ''
    START_TLS_OK = ''
    SHOULD_WAIT_FOR_SERVER_BANNER = True

    def do_pre_handshake(self, network_timeout):
        """Connect to a host on a given (SSL) port, send a STARTTLS command, and perform the SSL handshake.
        """
        super(GenericStartTLSConnection, self).do_pre_handshake(network_timeout)

        # Grab the banner
        if self.SHOULD_WAIT_FOR_SERVER_BANNER:
            self._sock.recv(2048)

        # Send Start TLS
        self._sock.send(self.START_TLS_CMD)
        if self.START_TLS_OK not in self._sock.recv(2048):
            raise StartTLSError(self.ERR_NO_STARTTLS)



class IMAPConnection(GenericStartTLSConnection):
    """SSL connection class that performs an IMAP StartTLS negotiation before the SSL handshake.
    """

    ERR_NO_STARTTLS = 'IMAP START TLS was rejected'

    START_TLS_CMD = '. STARTTLS\r\n'
    START_TLS_OK = '. OK'



class POP3Connection(GenericStartTLSConnection):
    """SSL connection class that performs a POP3 StartTLS negotiation before the SSL handshake.
    """

    ERR_NO_STARTTLS = 'POP START TLS was rejected'

    START_TLS_CMD = 'STLS\r\n'
    START_TLS_OK = '+OK'



class FTPConnection(GenericStartTLSConnection):
    """SSL connection class that performs an FTP StartTLS negotiation before the SSL handshake.
    """

    ERR_NO_STARTTLS = 'FTP AUTH TLS was rejected'

    START_TLS_CMD = 'AUTH TLS\r\n'
    START_TLS_OK = '234'



class PostgresConnection(GenericStartTLSConnection):
    """PostgreSQL SSL Connection.
    """

    ERR_NO_STARTTLS = 'Postgres AUTH TLS was rejected'

    START_TLS_CMD = bytearray(b'\x00\x00\x00\x08\x04\xD2\x16\x2F')
    START_TLS_OK = 'Start TLS request accepted.'
    SHOULD_WAIT_FOR_SERVER_BANNER = False
