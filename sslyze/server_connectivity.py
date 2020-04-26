from enum import Enum, unique, auto
from pathlib import Path
from typing import Optional

from dataclasses import dataclass

from nassl import _nassl
from nassl.ssl_client import ClientCertificateRequested

from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration
from sslyze.errors import (
    ServerRejectedTlsHandshake,
    ServerTlsConfigurationNotSupported,
    TlsHandshakeFailed,
    ConnectionToServerFailed,
)
from sslyze.connection_helpers.tls_connection import SslConnection


@unique
class ClientAuthRequirementEnum(Enum):
    """Whether the server asked for client authentication.
    """

    DISABLED = auto()
    OPTIONAL = auto()
    REQUIRED = auto()


@unique
class TlsVersionEnum(Enum):
    # WARNING: It has to be ordered and to match the values of nassl's OpenSslVersionEnum
    SSL_2_0 = 1
    SSL_3_0 = 2
    TLS_1_0 = 3
    TLS_1_1 = 4
    TLS_1_2 = 5
    TLS_1_3 = 6


@dataclass(frozen=True)
class ServerTlsProbingResult:
    """Additional details about the server, detected via connectivity testing.
    """

    highest_tls_version_supported: TlsVersionEnum
    cipher_suite_supported: str  # The OpenSSL name of a cipher suite supported by the server
    client_auth_requirement: ClientAuthRequirementEnum


@dataclass(frozen=True)
class ServerConnectivityInfo:
    """All the settings (hostname, port, SSL version, etc.) needed to successfully connect to a given SSL/TLS server.

    Such objects should never be instantiated directly and are instead returned by `ServerConnectivityTester.perform()`
    when connectivity testing was successful.

    Attributes:
        server_location: The minimum information needed to establish a connection to the server.
        network_configuration: Some additional configuration regarding how to connect to the server.
        tls_probing_result: Some additional details about the server's TLS configuration.
    """

    server_location: ServerNetworkLocation
    network_configuration: ServerNetworkConfiguration
    tls_probing_result: ServerTlsProbingResult

    def get_preconfigured_tls_connection(
        self,
        override_tls_version: Optional[TlsVersionEnum] = None,
        ca_certificates_path: Optional[Path] = None,
        should_use_legacy_openssl: Optional[bool] = None,
        should_enable_server_name_indication: bool = True,
    ) -> SslConnection:
        """Get an SSLConnection instance with the right SSL configuration for successfully connecting to the server.

        Used by all plugins to connect to the server and run scans.
        """
        final_ssl_version = self.tls_probing_result.highest_tls_version_supported
        final_openssl_cipher_string: Optional[str]
        final_openssl_cipher_string = self.tls_probing_result.cipher_suite_supported
        if override_tls_version is not None:
            # Caller wants to override the TLS version to use for this connection
            final_ssl_version = override_tls_version
            # Then we don't know which cipher suite is supported by the server for this ssl version
            final_openssl_cipher_string = None

        if should_use_legacy_openssl is not None:
            final_openssl_cipher_string = None

        if self.network_configuration.tls_client_auth_credentials is not None:
            # If we have creds for client authentication, go ahead and use them
            should_ignore_client_auth = False
        else:
            # Ignore client auth requests if the server allows optional TLS client authentication
            should_ignore_client_auth = True
            # But do not ignore them is client authentication is required so that the right exceptions get thrown
            # within the plugins, providing a better output
            if self.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.REQUIRED:
                should_ignore_client_auth = False

        ssl_connection = SslConnection(
            server_location=self.server_location,
            network_configuration=self.network_configuration,
            tls_version=final_ssl_version,
            should_ignore_client_auth=should_ignore_client_auth,
            ca_certificates_path=ca_certificates_path,
            should_use_legacy_openssl=should_use_legacy_openssl,
            should_enable_server_name_indication=should_enable_server_name_indication,
        )
        if final_openssl_cipher_string:
            ssl_connection.ssl_client.set_cipher_list(final_openssl_cipher_string)

        return ssl_connection


class ServerConnectivityTester:
    """Utility class to ensure that SSLyze is able to connect to a server before scanning it.
    """

    def perform(
        self, server_location: ServerNetworkLocation, network_configuration: Optional[ServerNetworkConfiguration] = None
    ) -> ServerConnectivityInfo:
        """Attempt to perform a full SSL/TLS handshake with the server.

        This method will ensure that the server can be reached, and will also identify one SSL/TLS version and one
        cipher suite that is supported by the server.

        Args:
            server_location
            network_configuration

        Returns:
            An object encapsulating all the information needed to connect to the server, to be passed to a `Scanner` in
            order to run scan commands against the server.

        Raises:
            ServerConnectivityError: If the server was not reachable or an SSL/TLS handshake could not be completed.
        """
        if network_configuration is None:
            final_network_config = ServerNetworkConfiguration.default_for_server_location(server_location)
        else:
            final_network_config = network_configuration

        # Try to complete an SSL handshake to figure out the SSL version and cipher supported by the server
        highest_tls_version_supported = None
        cipher_suite_supported = None
        client_auth_requirement = ClientAuthRequirementEnum.DISABLED

        # TODO(AD): Switch to using the protocol discovery logic available in OpenSSL 1.1.0 with TLS_client_method()
        for tls_version in [
            TlsVersionEnum.TLS_1_3,
            TlsVersionEnum.TLS_1_2,
            TlsVersionEnum.TLS_1_1,
            TlsVersionEnum.TLS_1_0,
            TlsVersionEnum.SSL_3_0,
        ]:
            # First try the default cipher list, and then all ciphers
            for cipher_list in [None, "ALL:COMPLEMENTOFALL:-PSK:-SRP"]:
                ssl_connection = SslConnection(
                    server_location=server_location,
                    network_configuration=final_network_config,
                    tls_version=tls_version,
                    should_ignore_client_auth=False,
                )
                if cipher_list:
                    if tls_version == TlsVersionEnum.TLS_1_3:
                        # Skip the second attempt with all ciphers enabled as these ciphers don't exist in TLS 1.3
                        continue

                    ssl_connection.ssl_client.set_cipher_list(cipher_list)

                try:
                    # Only do one attempt when testing connectivity
                    ssl_connection.connect(should_retry_connection=False)
                    highest_tls_version_supported = tls_version
                    cipher_suite_supported = ssl_connection.ssl_client.get_current_cipher_name()
                except ClientCertificateRequested:
                    # Connection successful but the servers wants a client certificate which wasn't supplied to sslyze
                    # Store the SSL version and cipher list that is supported
                    highest_tls_version_supported = tls_version
                    cipher_suite_supported = cipher_list
                    # Close the current connection and try again but ignore client authentication
                    ssl_connection.close()

                    # Try a new connection to see if client authentication is optional
                    ssl_connection_auth = SslConnection(
                        server_location=server_location,
                        network_configuration=final_network_config,
                        tls_version=tls_version,
                        should_ignore_client_auth=True,
                    )
                    if cipher_list:
                        ssl_connection_auth.ssl_client.set_cipher_list(cipher_list)
                    try:
                        ssl_connection_auth.connect(should_retry_connection=False)
                        cipher_suite_supported = ssl_connection_auth.ssl_client.get_current_cipher_name()
                        client_auth_requirement = ClientAuthRequirementEnum.OPTIONAL

                    # If client authentication is required, we either get a ClientCertificateRequested
                    except ClientCertificateRequested:
                        client_auth_requirement = ClientAuthRequirementEnum.REQUIRED
                    # Or a ServerRejectedTlsHandshake
                    except ServerRejectedTlsHandshake:
                        client_auth_requirement = ClientAuthRequirementEnum.REQUIRED
                    finally:
                        ssl_connection_auth.close()

                except TlsHandshakeFailed:
                    # This TLS version did not work; keep going
                    pass

                except (OSError, _nassl.OpenSSLError) as e:
                    # If these errors get propagated here, it means they're not part of the known/normal errors that
                    # can happen when trying to connect to a server and defined in tls_connection.py
                    # Hence we re-raise these as "unknown" connection errors; might be caused by bad connectivity to
                    # the server (random disconnects, etc.) and the scan against this server should not be performed
                    raise ConnectionToServerFailed(
                        server_location=server_location,
                        network_configuration=final_network_config,
                        error_message=f'Unexpected connection error: "{e.args}"',
                    )

                finally:
                    ssl_connection.close()

            if cipher_suite_supported:
                # A handshake was successful
                break

        if highest_tls_version_supported is None or cipher_suite_supported is None:
            raise ServerTlsConfigurationNotSupported(
                server_location=server_location,
                network_configuration=final_network_config,
                error_message="Probing failed: could not find a TLS version and cipher suite supported by the server",
            )
        tls_probing_result = ServerTlsProbingResult(
            highest_tls_version_supported=highest_tls_version_supported,
            cipher_suite_supported=cipher_suite_supported,
            client_auth_requirement=client_auth_requirement,
        )

        return ServerConnectivityInfo(
            server_location=server_location,
            network_configuration=final_network_config,
            tls_probing_result=tls_probing_result,
        )
