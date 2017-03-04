# -*- coding: utf-8 -*-
"""Settings to be used for configuring a server's ServerConnectivityInfo.
"""

from __future__ import absolute_import
from __future__ import unicode_literals

import os
from base64 import b64encode

from enum import Enum
from typing import Optional
from typing import Text

try:
    # Python 3
    # noinspection PyCompatibility
    from urllib.parse import urlparse
    from urllib.parse import quote
except ImportError:
    # Python 2
    # noinspection PyCompatibility
    from urlparse import urlparse
    from urllib import quote

from nassl.ssl_client import SslClient, OpenSslFileTypeEnum


class TlsWrappedProtocolEnum(Enum):
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
    """Container for specifying the settings to perform SSL/TLS client authentication with the server.
    """

    def __init__(self, client_certificate_chain_path, client_key_path, client_key_type=OpenSslFileTypeEnum.PEM,
                 client_key_password=''):
        # type: (Text, Text, OpenSslFileTypeEnum, Optional[Text]) -> None
        """
        Args:
            client_certificate_chain_path (Text): Path to the file containing the client's certificate.
            client_key_path (Text): Path to the file containing the client's private key.
            client_key_type (OpenSslFileTypeEnum): The format of the key file.
            client_key_password (Optional[Text]): The password to decrypt the private key.
        """
        self.client_certificate_chain_path = client_certificate_chain_path
        if not os.path.isfile(self.client_certificate_chain_path):
            raise ValueError('Could not open the client certificate file')

        self.client_key_path = client_key_path
        if not os.path.isfile(self.client_key_path):
            raise ValueError('Could not open the client private key file')

        self.client_key_password = client_key_password

        self.client_key_type = client_key_type
        if self.client_key_type not in OpenSslFileTypeEnum:
            raise ValueError('Invalid certificate format specified')

        # Try to load the cert and key in OpenSSL; will raise an exception if something is wrong
        SslClient(client_certchain_file=self.client_certificate_chain_path, client_key_file=self.client_key_path,
                  client_key_type=self.client_key_type, client_key_password=self.client_key_password)


class HttpConnectTunnelingSettings(object):
    """Container for specifying the settings to tunnel all traffic through an HTTP Connect Proxy.
    """

    def __init__(self, hostname, port, basic_auth_user=None, basic_auth_password=None):
        # type: (Text, int, Optional[Text], Optional[Text]) -> None
        """
        Args:
            hostname (Text): The proxy's hostname.
            port (int): The proxy's port.
            basic_auth_user (Optional[Text]): The username to use if the proxy requires Basic Authentication.
            basic_auth_password (Optional[Text]): The password to use if the proxy requires Basic Authentication.
        """
        self.hostname = hostname
        self.port = port
        self.basic_auth_user = basic_auth_user
        self.basic_auth_password = basic_auth_password


    @classmethod
    def from_url(cls, proxy_url):
        # type: (Text) -> HttpConnectTunnelingSettings
        parsed_url = urlparse(proxy_url)

        if not parsed_url.netloc or not parsed_url.hostname:
            raise ValueError('Invalid Proxy URL')

        if parsed_url.scheme == 'http':
            default_port = 80
        elif parsed_url.scheme == 'https':
            default_port = 443
        else:
            raise ValueError('Invalid URL scheme')

        port = parsed_url.port if parsed_url.port else default_port
        return cls(parsed_url.hostname, port, parsed_url.username, parsed_url.password)


    def get_basic_auth_header(self):
        # type: () -> Text
        """Generate the right HTTP header for Basic Authentication.
        """
        header = ''
        if self.basic_auth_user is not None:
            header = b64encode('{0}:{1}'.format(quote(self.basic_auth_user), quote(self.basic_auth_password)))
        return header
