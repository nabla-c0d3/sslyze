import socket
from enum import Enum
from pathlib import Path
from typing import Optional

from dataclasses import dataclass
from nassl.ssl_client import OpenSslVersionEnum, ClientCertificateRequested

from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration
from sslyze.utils.ssl_connection import SslHandshakeRejected, SslConnection, CouldNotConnectToHttpProxyError
from sslyze.utils.tls_wrapped_protocol_helpers import StartTlsError


class ClientAuthenticationServerConfigurationEnum(Enum):
    """Whether the server asked for client authentication.
    """
    DISABLED = 1
    OPTIONAL = 2
    REQUIRED = 3


@dataclass(frozen=True)
class ServerTlsProbingResult:
    """Additional details about the server, detected via connectivity testing.
    """
    highest_tls_version_supported: OpenSslVersionEnum
    openssl_cipher_string_supported: str
    client_auth_requirement: ClientAuthenticationServerConfigurationEnum


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

    def get_preconfigured_ssl_connection(
        self,
        override_tls_version: Optional[OpenSslVersionEnum] = None,
        ca_certificates_path: Optional[Path] = None,
        should_use_legacy_openssl: Optional[bool] = None,
    ) -> SslConnection:
        """Get an SSLConnection instance with the right SSL configuration for successfully connecting to the server.

        Used by all plugins to connect to the server and run scans.
        """
        final_ssl_version = self.tls_probing_result.highest_tls_version_supported
        final_openssl_cipher_string = self.tls_probing_result.openssl_cipher_string_supported
        if override_tls_version is not None:
            # Caller wants to override the ssl version to use for this connection
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
            if self.tls_probing_result.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.REQUIRED:
                should_ignore_client_auth = False

        ssl_connection = SslConnection(
            server_location=self.server_location,
            network_configuration=self.network_configuration,
            tls_version=final_ssl_version,
            should_ignore_client_auth=should_ignore_client_auth,
            ca_certificates_path=ca_certificates_path,
            should_use_legacy_openssl=should_use_legacy_openssl,
        )
        if final_openssl_cipher_string:
            ssl_connection.ssl_client.set_cipher_list(final_openssl_cipher_string)

        return ssl_connection


class ServerConnectivityError(Exception):
    """Error for when SSLyze was unable to successfully complete connectivity testing with the server.
    """

    def __init__(
        self,
        server_location: ServerNetworkLocation,
        network_configuration: ServerNetworkConfiguration,
        error_message: str
    ) -> None:
        self.server_location = server_location
        self.network_configuration = network_configuration
        self.error_message = error_message

    def __str__(self) -> str:
        return f"Could not connect to <{self.server_location}>: {self.error_message}."


class ServerRejectedConnection(ServerConnectivityError):
    pass


class ConnectionToServerTimedOut(ServerConnectivityError):
    pass


class ServerTlsConfigurationNotSupported(ServerConnectivityError):
    """The server was online but SSLyze was unable to find one TLS version and cipher suite supported by the server.

    This should never happen unless the server has a very exotic TLS configuration (such as supporting a very small
    set of niche cipher suites).
    """


class HttpProxyConnectivityError(ServerConnectivityError):
    pass


class ServerConnectivityTester:
    """Utility class to ensure that SSLyze is able to connect to a server before scanning it.
    """

    def perform(
        self,
        server_location: ServerNetworkLocation,
        network_configuration: Optional[ServerNetworkConfiguration] = None
    ) -> ServerConnectivityInfo:
        """Attempt to perform a full SSL/TLS handshake with the server.

        This method will ensure that the server can be reached, and will also identify one SSL/TLS version and one
        cipher suite that is supported by the server.

        Args:
            server_location
            network_configuration

        Returns:
            An object encapsulating all the information needed to connect to the server, to be
            passed to a `Scanner` in order to run scan commands against the server.

        Raises:
            ServerConnectivityError: If the server was not reachable or an SSL/TLS handshake could not be completed.
        """
        if network_configuration is None:
            final_network_config = ServerNetworkConfiguration.default_for_server_location(server_location)
        else:
            final_network_config = network_configuration

        # Then try to connect
        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.DISABLED
        ssl_connection = SslConnection(
            server_location=server_location,
            network_configuration=final_network_config,
            tls_version=OpenSslVersionEnum.SSLV23,
            should_ignore_client_auth=True,
        )

        # First only try a socket connection
        try:
            ssl_connection.do_pre_handshake()

        except socket.timeout:
            raise ConnectionToServerTimedOut(
                server_location,
                final_network_config,
                f"Connection timed out after {final_network_config.timeout} seconds"
            )
        except ConnectionError:
            raise ServerRejectedConnection(server_location, final_network_config, "Connection rejected")
        except StartTlsError as e:
            raise ServerTlsConfigurationNotSupported(server_location, final_network_config, e.args[0])
        except CouldNotConnectToHttpProxyError:
            raise HttpProxyConnectivityError(server_location, final_network_config, "Could not connect to HTTP proxy")
        except Exception as e:
            raise ServerConnectivityError(server_location, final_network_config, f"{e.args[0]}")

        finally:
            ssl_connection.close()

        # Then try to complete an SSL handshake to figure out the SSL version and cipher supported by the server
        highest_ssl_version_supported = None
        ssl_cipher_supported = None

        # TODO(AD): Switch to using the protocol discovery logic available in OpenSSL 1.1.0 with TLS_client_method()
        for ssl_version in [
            OpenSslVersionEnum.TLSV1_3,
            OpenSslVersionEnum.TLSV1_2,
            OpenSslVersionEnum.TLSV1_1,
            OpenSslVersionEnum.TLSV1,
            OpenSslVersionEnum.SSLV3,
            OpenSslVersionEnum.SSLV23,
        ]:
            # First try the default cipher list, and then all ciphers
            for cipher_list in [None, "ALL:COMPLEMENTOFALL:-PSK:-SRP"]:
                ssl_connection = SslConnection(
                    server_location=server_location,
                    network_configuration=final_network_config,
                    tls_version=ssl_version,
                    should_ignore_client_auth=False,
                )
                if cipher_list:
                    ssl_connection.ssl_client.set_cipher_list(cipher_list)

                try:
                    # Only do one attempt when testing connectivity
                    ssl_connection.connect()
                    highest_ssl_version_supported = ssl_version
                    ssl_cipher_supported = ssl_connection.ssl_client.get_current_cipher_name()
                except ClientCertificateRequested:
                    # Connection successful but the servers wants a client certificate which wasn't supplied to sslyze
                    # Store the SSL version and cipher list that is supported
                    highest_ssl_version_supported = ssl_version
                    ssl_cipher_supported = cipher_list
                    # Close the current connection and try again but ignore client authentication
                    ssl_connection.close()

                    # Try a new connection to see if client authentication is optional
                    ssl_connection_auth = SslConnection(
                        server_location=server_location,
                        network_configuration=final_network_config,
                        tls_version=ssl_version,
                        should_ignore_client_auth=True,
                    )
                    if cipher_list:
                        ssl_connection_auth.ssl_client.set_cipher_list(cipher_list)
                    try:
                        ssl_connection_auth.connect()
                        ssl_cipher_supported = ssl_connection_auth.ssl_client.get_current_cipher_name()
                        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.OPTIONAL

                    # If client authentication is required, we either get a ClientCertificateRequested
                    except ClientCertificateRequested:
                        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.REQUIRED
                    # Or a SSLHandshakeRejected
                    except SslHandshakeRejected:
                        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.REQUIRED
                    except Exception:
                        # Could not complete a handshake with this server
                        pass
                    finally:
                        ssl_connection_auth.close()

                except Exception:
                    # Could not complete a handshake with this server
                    pass
                finally:
                    ssl_connection.close()

            if ssl_cipher_supported:
                # A handshake was successful
                break

        if highest_ssl_version_supported is None or ssl_cipher_supported is None:
            raise ServerTlsConfigurationNotSupported(
                server_location, final_network_config, "Could not complete an SSL/TLS handshake with the server"
            )
        tls_probing_result = ServerTlsProbingResult(
            highest_tls_version_supported=highest_ssl_version_supported,
            openssl_cipher_string_supported=ssl_cipher_supported,
            client_auth_requirement=client_auth_requirement,
        )

        return ServerConnectivityInfo(
            server_location=server_location,
            network_configuration=final_network_config,
            tls_probing_result=tls_probing_result,
        )
