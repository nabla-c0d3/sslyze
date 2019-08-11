import socket
from typing import Optional, List, Iterable, cast

from nassl.ssl_client import OpenSslVersionEnum, ClientCertificateRequested

from sslyze.server_connectivity_info import ServerConnectivityInfo, ServerTlsProbingResult
from sslyze.server_setting import ServerNetworkLocation, ServerTlsConfiguration
from sslyze.utils.ssl_connection_configurator import SslConnectionConfigurator
from sslyze.ssl_settings import (
    TlsWrappedProtocolEnum,
    ClientAuthenticationCredentials,
    ClientAuthenticationServerConfigurationEnum,
)
from sslyze.utils.ssl_connection import SslHandshakeRejected, ProxyError
from sslyze.utils.thread_pool import ThreadPool
from sslyze.utils.tls_wrapped_protocol_helpers import StartTlsError


class ServerConnectivityError(Exception):
    """Generic error for when SSLyze was unable to successfully complete connectivity testing with the server.

    Attributes:
        server_info: The connectivity tester that failed, containing all the server's information
            (hostname, port, etc.) that was used to test connectivity.
        error_message: The error that was returned.
    """

    def __init__(self, server_info: "ServerConnectivityTester", error_message: str) -> None:
        self.server_info = server_info
        self.error_message = error_message

    def __str__(self) -> str:
        return '<{class_name}: server=({hostname}, {ip_addr}, {port}), error="{error_message}">'.format(
            class_name=self.__class__.__name__,
            hostname=self.server_info.hostname,
            ip_addr=self.server_info.ip_address,
            port=self.server_info.port,
            error_message=self.error_message,
        )


class ServerRejectedConnection(ServerConnectivityError):
    def __init__(self, server_info: "ServerConnectivityTester") -> None:
        super().__init__(server_info, "Connection rejected")


class ConnectionToServerTimedOut(ServerConnectivityError):
    def __init__(self, server_info: "ServerConnectivityTester") -> None:
        super().__init__(server_info, "Could not connect (timeout)")


class ServerHostnameCouldNotBeResolved(ServerConnectivityError):
    def __init__(self, server_info: "ServerConnectivityTester") -> None:
        super().__init__(server_info, "Could not resolve hostname")


class ServerTlsConfigurationNotSuportedError(ServerConnectivityError):
    """The server was online but SSLyze was unable to find one TLS version and cipher suite supported by the server.

    This should never happen unless the server has a very exotic TLS configuration (such as supporting a very small
    set of niche cipher suites).
    """


class ProxyConnectivityError(ServerConnectivityError):
    """The proxy was offline, or timed out, or rejected the connection while doing connectivity testing.
    """


# TODO: Remove self and turn into a function?
class ServerConnectivityTester:

    # TODO: Move this out
    TLS_DEFAULT_PORTS = {
        TlsWrappedProtocolEnum.PLAIN_TLS: 443,
        TlsWrappedProtocolEnum.STARTTLS_SMTP: 25,
        TlsWrappedProtocolEnum.STARTTLS_XMPP: 5222,
        TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER: 5269,
        TlsWrappedProtocolEnum.STARTTLS_FTP: 21,
        TlsWrappedProtocolEnum.STARTTLS_POP3: 110,
        TlsWrappedProtocolEnum.STARTTLS_LDAP: 389,
        TlsWrappedProtocolEnum.STARTTLS_IMAP: 143,
        TlsWrappedProtocolEnum.STARTTLS_RDP: 3389,
        TlsWrappedProtocolEnum.STARTTLS_POSTGRES: 5432,
    }

    def __init__(self, network_timeout: Optional[int] = None):
        self._network_timeout = network_timeout

    def perform(self, network_location: ServerNetworkLocation, tls_configuration: ServerTlsConfiguration) -> ServerConnectivityInfo:
        """Attempt to perform a full SSL/TLS handshake with the server.

        This method will ensure that the server can be reached, and will also identify one SSL/TLS version and one
        cipher suite that is supported by the server.

        Args:
            network_timeout: Network timeout value in seconds passed to the underlying socket.

        Returns:
            An object encapsulating all the information needed to connect to the server, to be
            passed to a `SynchronousScanner` or `ConcurrentScanner` in order to run scan commands on the server.

        Raises:
            ServerConnectivityError: If the server was not reachable or an SSL/TLS handshake could not be completed.
        """

        # Then try to connect
        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.DISABLED
        ssl_connection = SslConnectionConfigurator.get_connection(
            network_location=network_location,
            tls_configuration=tls_configuration,
            ssl_version=OpenSslVersionEnum.SSLV23,
            openssl_cipher_string=SslConnectionConfigurator.DEFAULT_SSL_CIPHER_LIST,
            should_ignore_client_auth=True,
        )

        # First only try a socket connection
        try:
            ssl_connection.do_pre_handshake(network_timeout=self._network_timeout)

        # Socket errors
        except socket.timeout:  # Host is down
            raise ConnectionToServerTimedOut(self)
        except ConnectionError:
            raise ServerRejectedConnection(self)

        # StartTLS errors
        except StartTlsError as e:
            raise ServerTlsConfigurationNotSuportedError(self, e.args[0])

        # Proxy errors
        except ProxyError as e:
            raise ProxyConnectivityError(self, e.args[0])

        # Other errors
        except Exception as e:
            raise ServerConnectivityError(self, "{0}: {1}".format(str(type(e).__name__), e.args[0]))

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
            for cipher_list in [SslConnectionConfigurator.DEFAULT_SSL_CIPHER_LIST, "ALL:COMPLEMENTOFALL:-PSK:-SRP"]:
                ssl_connection = SslConnectionConfigurator.get_connection(
                    network_location=network_location,
                    tls_configuration=tls_configuration,
                    ssl_version=ssl_version,
                    openssl_cipher_string=cipher_list,
                    should_ignore_client_auth=False,
                )
                try:
                    # Only do one attempt when testing connectivity
                    ssl_connection.connect(network_timeout=self._network_timeout, network_max_retries=0)
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
                    ssl_connection_auth = SslConnectionConfigurator.get_connection(
                        network_location=network_location,
                        tls_configuration=tls_configuration,
                        ssl_version=ssl_version,
                        openssl_cipher_string=cipher_list,
                        should_ignore_client_auth=True,
                    )
                    try:
                        ssl_connection_auth.connect(network_timeout=self._network_timeout, network_max_retries=0)
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
            raise ServerTlsConfigurationNotSuportedError(
                self, "Could not complete an SSL/TLS handshake with the server"
            )
        tls_probing_result = ServerTlsProbingResult(
            highest_ssl_version_supported=highest_ssl_version_supported,
            openssl_cipher_string_supported=ssl_cipher_supported,
            client_auth_requirement=client_auth_requirement,
        )

        return ServerConnectivityInfo(
            network_location=network_location,
            tls_configuration=tls_configuration,
            tls_probing_result=tls_probing_result,
        )


class ConcurrentServerConnectivityTester:
    """Utility class to run servers connectivity testing using a thread pool.
    """

    _DEFAULT_MAX_THREADS = 20

    def __init__(self, server_connectivity_testers: List[ServerConnectivityTester]) -> None:
        # Use a thread pool to connect to each server
        self._thread_pool = ThreadPool()
        self._server_connectivity_testers = server_connectivity_testers

    def start_connectivity_testing(
        self, max_threads: int = _DEFAULT_MAX_THREADS, network_timeout: Optional[int] = None
    ) -> None:
        for server_tester in self._server_connectivity_testers:
            self._thread_pool.add_job((server_tester.perform, [network_timeout]))
        nb_threads = min(len(self._server_connectivity_testers), max_threads)
        self._thread_pool.start(nb_threads)

    def get_reachable_servers(self) -> Iterable[ServerConnectivityInfo]:
        for (_, server_info) in self._thread_pool.get_result():
            yield server_info

    def get_invalid_servers(self) -> Iterable[ServerConnectivityError]:
        for (_, exception) in self._thread_pool.get_error():
            yield cast(ServerConnectivityError, exception)
