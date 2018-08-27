"""Settings to be used for configuring a server's ServerConnectivityInfo.
"""

import os

from enum import Enum
from typing import Optional

from urllib.parse import urlparse

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


class ClientAuthenticationServerConfigurationEnum(Enum):
    """Whether the server asked for client authentication.
    """
    DISABLED = 1
    OPTIONAL = 2
    REQUIRED = 3


class ClientAuthenticationCredentials:
    """Container for specifying the settings to perform SSL/TLS client authentication with the server.
    """

    def __init__(
            self,
            client_certificate_chain_path: str,
            client_key_path: str,
            client_key_type: OpenSslFileTypeEnum = OpenSslFileTypeEnum.PEM,
            client_key_password: str = ''
    ) -> None:
        """
        Args:
            client_certificate_chain_path: Path to the file containing the client's certificate.
            client_key_path: Path to the file containing the client's private key.
            client_key_type: The format of the key file.
            client_key_password: The password to decrypt the private key.
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
        SslClient(
            client_certchain_file=self.client_certificate_chain_path,
            client_key_file=self.client_key_path,
            client_key_type=self.client_key_type,
            client_key_password=self.client_key_password
        )

    def __str__(self) -> str:
        return '<{class_name}: cert_path="{cert_path}", key_path="{key_path}">'.format(
            class_name=self.__class__.__name__,
            cert_path=self.client_certificate_chain_path,
            key_path=self.client_key_path,
        )


class HttpConnectTunnelingSettings:
    """Container for specifying the settings to tunnel all traffic through an HTTP Connect Proxy.
    """

    def __init__(
            self,
            hostname: str,
            port: int,
            basic_auth_user: Optional[str] = None,
            basic_auth_password: Optional[str] = None
    ) -> None:
        """
        Args:
            hostname: The proxy's hostname.
            port: The proxy's port.
            basic_auth_user: The username to use if the proxy requires Basic Authentication.
            basic_auth_password: The password to use if the proxy requires Basic Authentication.
        """
        self.hostname = hostname
        self.port = port
        self.basic_auth_user = basic_auth_user
        self.basic_auth_password = basic_auth_password

    def __str__(self) -> str:
        return '<{class_name}: proxy_server=({hostname}, {port}), username="{user}">'.format(
            class_name=self.__class__.__name__,
            hostname=self.hostname,
            port=self.port,
            user=self.basic_auth_user,
        )

    @classmethod
    def from_url(cls, proxy_url: str) -> 'HttpConnectTunnelingSettings':
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
