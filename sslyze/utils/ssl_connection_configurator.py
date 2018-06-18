from typing import Union, Optional

from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import OpenSslVersionEnum, SslClient, OpenSslVerifyEnum

from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.utils.connection_helpers import ProxyTunnelingConnectionHelper, DirectConnectionHelper, ConnectionHelper
from sslyze.utils.ssl_connection import SslConnection

from typing import TYPE_CHECKING

from sslyze.utils.tls_wrapped_protocol_helpers import SmtpHelper, HttpsHelper, XmppHelper, XmppServerHelper,\
    Pop3Helper, ImapHelper, FtpHelper, LdapHelper, RdpHelper, PostgresHelper, TlsHelper

if TYPE_CHECKING:
    from sslyze.server_connectivity_info import ServerConnectivityInfo  # noqa: F401
    from sslyze.server_connectivity_tester import ServerConnectivityTester  # noqa: F401


class SslConnectionConfigurator:
    """Utility class to create the right SSL Connection object for a given server.
    """

    START_TLS_HELPER_CLASSES = {
        TlsWrappedProtocolEnum.PLAIN_TLS: TlsHelper,
        TlsWrappedProtocolEnum.HTTPS: HttpsHelper,
        TlsWrappedProtocolEnum.STARTTLS_SMTP: SmtpHelper,
        TlsWrappedProtocolEnum.STARTTLS_XMPP: XmppHelper,
        TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER: XmppServerHelper,
        TlsWrappedProtocolEnum.STARTTLS_POP3: Pop3Helper,
        TlsWrappedProtocolEnum.STARTTLS_IMAP: ImapHelper,
        TlsWrappedProtocolEnum.STARTTLS_FTP: FtpHelper,
        TlsWrappedProtocolEnum.STARTTLS_LDAP: LdapHelper,
        TlsWrappedProtocolEnum.STARTTLS_RDP: RdpHelper,
        TlsWrappedProtocolEnum.STARTTLS_POSTGRES: PostgresHelper,
    }

    # Restrict cipher list to make the client hello smaller so we don't run into
    # https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=665452
    DEFAULT_SSL_CIPHER_LIST = 'HIGH:MEDIUM:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA'

    @classmethod
    def get_connection(
            cls,
            ssl_version: OpenSslVersionEnum,

            # This method leverages the fact that ServerConnectivityInfo and ServerConnectivityTester have attributes
            # with the same names (hacky)
            server_info: Union['ServerConnectivityInfo', 'ServerConnectivityTester'],

            should_ignore_client_auth: bool,
            openssl_cipher_string: Optional[str] = None,
            ssl_verify_locations: Optional[str] = None,
            should_use_legacy_openssl: Optional[bool] = None,
    ) -> SslConnection:
        # We need three things to create an SSL connection

        # 1. Create the connection helper
        connection_helper: ConnectionHelper
        if server_info.http_tunneling_settings:
            connection_helper = ProxyTunnelingConnectionHelper(
                server_info.hostname, server_info.port, server_info.http_tunneling_settings
            )
        else:
            if server_info.ip_address is None:
                # We received a ServerConnectivityTester whose perform() method has not been called; should never happen
                raise ValueError('Received ServerConnectivityTester with a None ip_address')
            connection_helper = DirectConnectionHelper(server_info.ip_address, server_info.port)

        # 2. Create the StartTLS helper
        start_tls_helper = cls.START_TLS_HELPER_CLASSES[server_info.tls_wrapped_protocol](  # type: ignore
            server_info.hostname
        )

        if isinstance(start_tls_helper, XmppHelper) and server_info.xmpp_to_hostname:
            start_tls_helper.override_xmpp_to(server_info.xmpp_to_hostname)

        # 3. Create the SSL client
        if should_use_legacy_openssl is None:
            # For older versions of TLS/SSL, we have to use a legacy OpenSSL
            final_should_use_legacy_openssl = False if ssl_version in [OpenSslVersionEnum.TLSV1_2,
                                                                       OpenSslVersionEnum.TLSV1_3] \
                else True
        else:
            final_should_use_legacy_openssl = should_use_legacy_openssl
        ssl_client_cls = LegacySslClient if final_should_use_legacy_openssl else SslClient

        if server_info.client_auth_credentials:
            # A client certificate and private key were provided
            ssl_client = ssl_client_cls(
                ssl_version=ssl_version,
                ssl_verify=OpenSslVerifyEnum.NONE,
                ssl_verify_locations=ssl_verify_locations,
                client_certchain_file=server_info.client_auth_credentials.client_certificate_chain_path,
                client_key_file=server_info.client_auth_credentials.client_key_path,
                client_key_type=server_info.client_auth_credentials.client_key_type,
                client_key_password=server_info.client_auth_credentials.client_key_password,
                ignore_client_authentication_requests=False
            )
        else:
            # No client cert and key
            ssl_client = ssl_client_cls(
                ssl_version=ssl_version,
                ssl_verify=OpenSslVerifyEnum.NONE,
                ssl_verify_locations=ssl_verify_locations,
                ignore_client_authentication_requests=should_ignore_client_auth
            )

        # Add Server Name Indication
        if ssl_version != OpenSslVersionEnum.SSLV2:
            ssl_client.set_tlsext_host_name(server_info.tls_server_name_indication)

        ssl_client.set_cipher_list(openssl_cipher_string if openssl_cipher_string else cls.DEFAULT_SSL_CIPHER_LIST)

        # All done
        ssl_connection = SslConnection(connection_helper, start_tls_helper, ssl_client)
        return ssl_connection
