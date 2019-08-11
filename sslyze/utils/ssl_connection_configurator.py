from pathlib import Path
from typing import Optional

from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import OpenSslVersionEnum, SslClient, OpenSslVerifyEnum

from sslyze.server_setting import ServerTlsConfiguration, ServerNetworkLocation
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.utils.ssl_connection import SslConnection

from typing import TYPE_CHECKING

from sslyze.utils.tls_wrapped_protocol_helpers import (
    SmtpHelper,
    HttpsHelper,
    XmppHelper,
    XmppServerHelper,
    Pop3Helper,
    ImapHelper,
    FtpHelper,
    LdapHelper,
    RdpHelper,
    PostgresHelper,
    TlsHelper,
)


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
    DEFAULT_SSL_CIPHER_LIST = "HIGH:MEDIUM:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA"

    @classmethod
    def get_connection(
        cls,
        network_location: ServerNetworkLocation,
        tls_configuration: ServerTlsConfiguration,
        ssl_version: OpenSslVersionEnum,
        openssl_cipher_string: Optional[str],
        should_ignore_client_auth: bool,
        ssl_verify_locations: Optional[Path] = None,
        should_use_legacy_openssl: Optional[bool] = None,
    ) -> SslConnection:
        ssl_verify_locations_str = str(ssl_verify_locations) if ssl_verify_locations else None

        # Create the StartTLS helper
        start_tls_helper_cls = cls.START_TLS_HELPER_CLASSES[tls_configuration.tls_wrapped_protocol]
        if start_tls_helper_cls in [XmppHelper, XmppServerHelper]:
            start_tls_helper = start_tls_helper_cls(
                server_hostname=network_location.hostname, xmpp_to=tls_configuration.xmpp_to_hostname
            )
        else:
            start_tls_helper = start_tls_helper_cls(server_hostname=network_location.hostname)

        # Create the SSL client
        # For older versions of TLS/SSL, we have to use a legacy OpenSSL
        if should_use_legacy_openssl is None:
            # For older versions of TLS/SSL, we have to use a legacy OpenSSL
            final_should_use_legacy_openssl = (
                False if ssl_version in [OpenSslVersionEnum.TLSV1_2, OpenSslVersionEnum.TLSV1_3] else True
            )
        else:
            final_should_use_legacy_openssl = should_use_legacy_openssl

        ssl_client_cls = LegacySslClient if final_should_use_legacy_openssl else SslClient

        if tls_configuration.client_auth_credentials:
            # A client certificate and private key were provided
            ssl_client = ssl_client_cls(
                ssl_version=ssl_version,
                ssl_verify=OpenSslVerifyEnum.NONE,
                ssl_verify_locations=ssl_verify_locations_str,
                client_certchain_file=tls_configuration.client_auth_credentials.client_certificate_chain_path,
                client_key_file=tls_configuration.client_auth_credentials.client_key_path,
                client_key_type=tls_configuration.client_auth_credentials.client_key_type,
                client_key_password=tls_configuration.client_auth_credentials.client_key_password,
                ignore_client_authentication_requests=False,
            )
        else:
            # No client cert and key
            ssl_client = ssl_client_cls(
                ssl_version=ssl_version,
                ssl_verify=OpenSslVerifyEnum.NONE,
                ssl_verify_locations=ssl_verify_locations_str,
                ignore_client_authentication_requests=should_ignore_client_auth,
            )

        # Add Server Name Indication
        if ssl_version != OpenSslVersionEnum.SSLV2:
            ssl_client.set_tlsext_host_name(tls_configuration.tls_server_name_indication)

        if openssl_cipher_string:
            ssl_client.set_cipher_list(openssl_cipher_string)
        else:
            ssl_client.set_cipher_list(cls.DEFAULT_SSL_CIPHER_LIST)

        # All done
        ssl_connection = SslConnection(network_location, start_tls_helper, ssl_client)
        return ssl_connection
