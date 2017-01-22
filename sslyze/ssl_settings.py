# -*- coding: utf-8 -*-
"""Settings to be used for configuring an SSL connection via the ServerConnectivityInfo class.
"""

import os
from base64 import b64encode
from urllib import quote
from typing import Optional

try:
    # Python 3
    # noinspection PyCompatibility
    from urllib.parse import urlparse
except ImportError:
    # Python 2
    # noinspection PyCompatibility
    from urlparse import urlparse

from nassl import SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1
from nassl.ssl_client import SslClient


class TlsWrappedProtocolEnum(object):
    """The list of TLS-wrapped protocols supported by SSLyze.

    SSLyze uses this to figure out how to establish an SSL/TLS connection to the server and what kind of "hello" message
    to send after the handshake was completed.
    """
    PLAIN_TLS = 1  # Standard TLS connection
    HTTPS = 2
    STARTTLS_SMTP = 3
    STARTTLS_XMPP = 4
    STARTTLS_XMPP_SERVER = 5
    STARTTLS_FTP = 6
    STARTTLS_POP3 = 7
    STARTTLS_LDAP = 8
    STARTTLS_IMAP = 9
    STARTTLS_RDP = 10
    STARTTLS_POSTGRES = 11


class ClientAuthenticationCredentials(object):
    """Parameters needed to perform SSL/TLS client/mutual authentication with a server.
    """

    def __init__(self, client_certificate_chain_path, client_key_path, client_key_type=SSL_FILETYPE_PEM,
                 client_key_password=''):
        # type: (str, str, int, Optional[str]) -> None
        """Create a container for SSL/TLS client authentication settings.

        Args:
            client_certificate_chain_path (str): Path to the client's certificate chain.
            client_key_path (str): Path to the client's private key.
            client_key_type (int): SSL_FILETYPE_PEM or SSL_FILETYPE_DER.
            client_key_password (Optional[str]): Password needed to decrypt the private key.
        """
        self.client_certificate_chain_path = client_certificate_chain_path
        if not os.path.isfile(self.client_certificate_chain_path):
            raise ValueError('Could not open the client certificate file')

        self.client_key_path = client_key_path
        if not os.path.isfile(self.client_key_path):
            raise ValueError('Could not open the client private key file')

        self.client_key_password = client_key_password

        self.client_key_type = client_key_type
        if self.client_key_type not in [SSL_FILETYPE_ASN1, SSL_FILETYPE_PEM]:
            raise ValueError('Invalid certificate format specified')

        # Try to load the cert and key in OpenSSL; will raise an exception if something is wrong
        SslClient(client_certchain_file=self.client_certificate_chain_path, client_key_file=self.client_key_path,
                  client_key_type=self.client_key_type, client_key_password=self.client_key_password)


class HttpConnectTunnelingSettings(object):
    """Parameters needed to tunnel SSL/TLS traffic through an HTTP Connect Proxy.
    """

    def __init__(self, hostname, port, basic_auth_user=None, basic_auth_password=None):
        # type: (unicode, int, Optional[str], Optional[str]) -> None
        self.hostname = hostname
        self.port = port
        self.basic_auth_user = basic_auth_user
        self.basic_auth_password = basic_auth_password


    @classmethod
    def from_url(cls, proxy_url):
        # type: (unicode) -> HttpConnectTunnelingSettings
        parsed_url = urlparse(proxy_url)

        if not parsed_url.netloc or not parsed_url.hostname:
            raise ValueError(u'Invalid Proxy URL.')

        if parsed_url.scheme == u'http':
           default_port = 80
        elif parsed_url.scheme == u'https':
           default_port = 443
        else:
            raise ValueError(u'Invalid URL scheme')

        port = parsed_url.port if parsed_url.port else default_port
        return cls(parsed_url.hostname, port, parsed_url.username, parsed_url.password)


    def get_basic_auth_header(self):
        """Generate the right HTTP header for Basic Authentication.
        """
        header = ''
        if self.basic_auth_user is not None:
            header = b64encode('{0}:{1}'.format(quote(self.basic_auth_user), quote(self.basic_auth_password)))
        return header