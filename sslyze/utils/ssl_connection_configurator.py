from __future__ import absolute_import
from __future__ import unicode_literals

from typing import Union, Optional, Text

from nassl.ssl_client import OpenSslVersionEnum

from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.utils.ssl_connection import SSLConnection, HTTPSConnection, SMTPConnection, XMPPConnection, \
    XMPPServerConnection, POP3Connection, IMAPConnection, FTPConnection, LDAPConnection, RDPConnection, \
    PostgresConnection

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from sslyze.server_connectivity_info import ServerConnectivityInfo
    from sslyze.server_connectivity_tester import ServerConnectivityTester


class SslConnectionConfigurator(object):
    """Utility class to create the right SSL Connection object for a given server.
    """

    TLS_CONNECTION_CLASSES = {
        TlsWrappedProtocolEnum.PLAIN_TLS: SSLConnection,
        TlsWrappedProtocolEnum.HTTPS: HTTPSConnection,
        TlsWrappedProtocolEnum.STARTTLS_SMTP: SMTPConnection,
        TlsWrappedProtocolEnum.STARTTLS_XMPP: XMPPConnection,
        TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER: XMPPServerConnection,
        TlsWrappedProtocolEnum.STARTTLS_POP3: POP3Connection,
        TlsWrappedProtocolEnum.STARTTLS_IMAP: IMAPConnection,
        TlsWrappedProtocolEnum.STARTTLS_FTP: FTPConnection,
        TlsWrappedProtocolEnum.STARTTLS_LDAP: LDAPConnection,
        TlsWrappedProtocolEnum.STARTTLS_RDP: RDPConnection,
        TlsWrappedProtocolEnum.STARTTLS_POSTGRES: PostgresConnection,
    }

    @classmethod
    def get_connection(
            cls,
            ssl_version,                        # type: OpenSslVersionEnum
            server_info,                        # type: Union[ServerConnectivityInfo, ServerConnectivityTester]
            should_ignore_client_auth,          # type: bool
            openssl_cipher_string=None,         # type: Optional[Text]
            ssl_verify_locations=None,          # type: Optional[Text]
            should_use_legacy_openssl=None,     # type: Optional[bool]
    ):
        # type: (...) -> SSLConnection
        if not server_info.ip_address and not server_info.http_tunneling_settings:
            # We received a ServerConnectivityTester whose perform() method has not been called; should never happen
            raise ValueError('Received ServerConnectivityTester with a None ip_address')

        # This method leverages the fact that ServerConnectivityInfo and ServerConnectivityTester have attributes with
        # the same names
        if should_use_legacy_openssl is None:
            # For older versions of TLS/SSL, we have to use a legacy OpenSSL
            final_should_use_legacy_openssl = False if ssl_version in [OpenSslVersionEnum.TLSV1_2,
                                                                       OpenSslVersionEnum.TLSV1_3] \
                else True
        else:
            final_should_use_legacy_openssl = should_use_legacy_openssl

        ssl_connection = cls.TLS_CONNECTION_CLASSES[server_info.tls_wrapped_protocol](
            server_info.hostname,
            server_info.ip_address,
            server_info.port,
            ssl_version,
            ssl_verify_locations=ssl_verify_locations,
            client_auth_creds=server_info.client_auth_credentials,
            should_ignore_client_auth=should_ignore_client_auth,
            should_use_legacy_openssl=final_should_use_legacy_openssl,
        )

        # Add XMPP configuration
        if isinstance(ssl_connection, XMPPConnection) and server_info.xmpp_to_hostname:
            ssl_connection.set_xmpp_to(server_info.xmpp_to_hostname)

        # Add HTTP tunneling configuration
        if server_info.http_tunneling_settings:
            ssl_connection.enable_http_connect_tunneling(server_info.http_tunneling_settings.hostname,
                                                         server_info.http_tunneling_settings.port,
                                                         server_info.http_tunneling_settings.basic_auth_user,
                                                         server_info.http_tunneling_settings.basic_auth_password)

        # Add Server Name Indication
        if ssl_version != OpenSslVersionEnum.SSLV2:
            ssl_connection.ssl_client.set_tlsext_host_name(server_info.tls_server_name_indication)

        # Add well-known supported cipher suite
        if openssl_cipher_string:
            ssl_connection.ssl_client.set_cipher_list(openssl_cipher_string)

        return ssl_connection
