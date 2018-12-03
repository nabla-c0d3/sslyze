import socket
from typing import Optional, List, Iterable, cast

from nassl.ssl_client import OpenSslVersionEnum, ClientCertificateRequested

from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.utils.connection_helpers import ProxyError
from sslyze.utils.ssl_connection_configurator import SslConnectionConfigurator
from sslyze.ssl_settings import TlsWrappedProtocolEnum, ClientAuthenticationCredentials, HttpConnectTunnelingSettings, \
    ClientAuthenticationServerConfigurationEnum
from sslyze.utils.ssl_connection import SslHandshakeRejected
from sslyze.utils.thread_pool import ThreadPool
from sslyze.utils.tls_wrapped_protocol_helpers import StartTlsError


class ServerConnectivityError(Exception):
    """Generic error for when SSLyze was unable to successfully complete connectivity testing with the server.

    Attributes:
        server_info: The connectivity tester that failed, containing all the server's information
            (hostname, port, etc.) that was used to test connectivity.
        error_message: The error that was returned.
    """

    def __init__(self, server_info: 'ServerConnectivityTester', error_message: str) -> None:
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

    def __init__(self, server_info: 'ServerConnectivityTester') -> None:
        super().__init__(server_info, 'Connection rejected')


class ConnectionToServerTimedOut(ServerConnectivityError):

    def __init__(self, server_info: 'ServerConnectivityTester') -> None:
        super().__init__(server_info, 'Could not connect (timeout)')


class ServerHostnameCouldNotBeResolved(ServerConnectivityError):

    def __init__(self, server_info: 'ServerConnectivityTester') -> None:
        super().__init__(server_info, 'Could not resolve hostname')


class ServerTlsConfigurationNotSuportedError(ServerConnectivityError):
    """The server was online but SSLyze was unable to find one TLS version and cipher suite supported by the server.

    This should never happen unless the server has a very exotic TLS configuration (such as supporting a very small
    set of niche cipher suites).
    """


class ProxyConnectivityError(ServerConnectivityError):
    """The proxy was offline, or timed out, or rejected the connection while doing connectivity testing.
    """


class ServerConnectivityTester:

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
        TlsWrappedProtocolEnum.STARTTLS_POSTGRES: 5432
    }

    def __str__(self) -> str:
        return '<{class_name}: server=({hostname}, {ip_addr}, {port})>'.format(
            class_name=self.__class__.__name__,
            hostname=self.hostname,
            ip_addr=self.ip_address,
            port=self.port,
        )

    def __init__(
            self,
            hostname: str,
            port: Optional[int] = None,
            ip_address: Optional[str] = None,
            tls_wrapped_protocol: TlsWrappedProtocolEnum = TlsWrappedProtocolEnum.PLAIN_TLS,
            tls_server_name_indication: Optional[str] = None,
            xmpp_to_hostname: Optional[str] = None,
            client_auth_credentials: Optional[ClientAuthenticationCredentials] = None,
            http_tunneling_settings: Optional[HttpConnectTunnelingSettings] = None,
    ) -> None:
        """Constructor to specify how to connect to a given SSL/TLS server to be scanned.

        Most arguments are optional but can be supplied in order to be more specific about the server's configuration.

        After initialization, the `perform()` method must be called next to ensure that the
        server is actually reachable. The `ServerConnectivityInfo` returned by `perform()` can then be passed to a
        `SynchronousScanner` or `ConcurrentScanner` in order to run scan commands on the server.

        Args:
            hostname: The server's hostname.
            port: The server's TLS port number. If not supplied, the default port number for the specified
                `tls_wrapped_protocol` will be used.
            ip_address: The server's IP address. If not supplied, a DNS lookup for the specified `hostname` will be
                performed. If `http_tunneling_settings` is specified, `ip_address` cannot be supplied as the HTTP proxy
                will be responsible for looking up and connecting to the server to be scanned.
            tls_wrapped_protocol: The protocol wrapped in TLS that the server expects. It allows sslyze to figure out
                how to establish a (Start)TLS connection to the server and what kind of "hello" message
                (SMTP, XMPP, etc.) to send to the server after the handshake was completed. If not supplied, standard
                TLS will be used.
            tls_server_name_indication: The hostname to set within the Server Name Indication TLS extension. If not
                supplied, the specified `hostname` will be used.
            xmpp_to_hostname: The hostname to set within the `to` attribute of the XMPP stream. If not supplied, the
                specified `hostname` will be used. Should only be set if the supplied `tls_wrapped_protocol` is an
                XMPP protocol.
            client_auth_credentials: The client certificate and private key needed to perform mutual authentication
                with the server. If not supplied, sslyze will attempt to connect to the server without performing
                mutual authentication.
            http_tunneling_settings: The HTTP proxy configuration to use in order to tunnel the scans through a proxy.
                If not supplied, sslyze will run the scans by directly connecting to the server.

        Raises:
            ValueError: If `xmpp_to_hostname` was specified for a non-XMPP protocol.
            ValueError: If both `ip_address` and `http_tunneling_settings` were supplied.
        """
        # Store the hostname in ACE format in the case the domain name is unicode
        self.hostname = hostname.encode('idna').decode('utf-8')
        self.tls_wrapped_protocol = tls_wrapped_protocol
        self.port = port if port else self.TLS_DEFAULT_PORTS[tls_wrapped_protocol]

        if ip_address and http_tunneling_settings:
            raise ValueError('Cannot specify both ip_address and http_tunneling_settings.')
        self.ip_address = ip_address

        # Use the hostname as the default SNI
        self.tls_server_name_indication = tls_server_name_indication if tls_server_name_indication else self.hostname

        self.xmpp_to_hostname = xmpp_to_hostname
        if self.xmpp_to_hostname and self.tls_wrapped_protocol not in [TlsWrappedProtocolEnum.STARTTLS_XMPP,
                                                                       TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER]:
            raise ValueError('Can only specify xmpp_to for the XMPP StartTLS protocol.')

        self.client_auth_credentials = client_auth_credentials
        self.http_tunneling_settings = http_tunneling_settings

    @classmethod
    def _do_dns_lookup(cls, hostname: str, port: int) -> str:
        addr_infos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.IPPROTO_IP)
        family, socktype, proto, canonname, sockaddr = addr_infos[0]

        # By default use the first DNS entry, IPv4 or IPv6
        tentative_ip_addr = sockaddr[0]

        # But try to use IPv4 if we have both IPv4 and IPv6 addresses, to work around buggy networks
        for family, socktype, proto, canonname, sockaddr in addr_infos:
            if family == socket.AF_INET:
                tentative_ip_addr = sockaddr[0]

        return tentative_ip_addr

    def perform(self, network_timeout: Optional[int] = None) -> ServerConnectivityInfo:
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
        # First do a DNS lookup if we don't already have an IP address and we are not using a proxy
        if not self.ip_address and not self.http_tunneling_settings:
            try:
                self.ip_address = self._do_dns_lookup(self.hostname, self.port)
            except (socket.gaierror, IndexError, ConnectionError):
                raise ServerHostnameCouldNotBeResolved(self)

        # Then try to connect
        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.DISABLED
        ssl_connection = SslConnectionConfigurator.get_connection(
            ssl_version=OpenSslVersionEnum.SSLV23,
            server_info=self,
            should_ignore_client_auth=True,
        )

        # First only try a socket connection
        try:
            ssl_connection.do_pre_handshake(network_timeout=network_timeout)

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
            raise ServerConnectivityError(self, '{0}: {1}'.format(str(type(e).__name__), e.args[0]))

        finally:
            ssl_connection.close()

        # Then try to complete an SSL handshake to figure out the SSL version and cipher supported by the server
        ssl_version_supported = None
        ssl_cipher_supported = None

        # TODO(AD): Switch to using the protocol discovery logic available in OpenSSL 1.1.0 with TLS_client_method()
        for ssl_version in [
            OpenSslVersionEnum.TLSV1_3,
            OpenSslVersionEnum.TLSV1_2,
            OpenSslVersionEnum.TLSV1_1,
            OpenSslVersionEnum.TLSV1,
            OpenSslVersionEnum.SSLV3,
            OpenSslVersionEnum.SSLV23
        ]:
            # First try the default cipher list, and then all ciphers
            for cipher_list in [SslConnectionConfigurator.DEFAULT_SSL_CIPHER_LIST, 'ALL:COMPLEMENTOFALL:-PSK:-SRP']:
                ssl_connection = SslConnectionConfigurator.get_connection(
                    ssl_version=ssl_version,
                    server_info=self,
                    openssl_cipher_string=cipher_list,
                    should_ignore_client_auth=False,
                )
                try:
                    # Only do one attempt when testing connectivity
                    ssl_connection.connect(network_timeout=network_timeout, network_max_retries=0)
                    ssl_version_supported = ssl_version
                    ssl_cipher_supported = ssl_connection.ssl_client.get_current_cipher_name()
                except ClientCertificateRequested:
                    # Connection successful but the servers wants a client certificate which wasn't supplied to sslyze
                    # Store the SSL version and cipher list that is supported
                    ssl_version_supported = ssl_version
                    ssl_cipher_supported = cipher_list
                    # Close the current connection and try again but ignore client authentication
                    ssl_connection.close()

                    # Try a new connection to see if client authentication is optional
                    ssl_connection_auth = SslConnectionConfigurator.get_connection(
                        ssl_version=ssl_version,
                        server_info=self,
                        openssl_cipher_string=cipher_list,
                        should_ignore_client_auth=True,
                    )
                    try:
                        ssl_connection_auth.connect(network_timeout=network_timeout, network_max_retries=0)
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

        if ssl_version_supported is None or ssl_cipher_supported is None:
            raise ServerTlsConfigurationNotSuportedError(
                self, 'Could not complete an SSL/TLS handshake with the server'
            )

        return ServerConnectivityInfo(
            hostname=self.hostname,
            port=self.port,
            ip_address=self.ip_address,
            tls_wrapped_protocol=self.tls_wrapped_protocol,
            tls_server_name_indication=self.tls_server_name_indication,
            highest_ssl_version_supported=ssl_version_supported,
            openssl_cipher_string_supported=ssl_cipher_supported,
            client_auth_requirement=client_auth_requirement,
            xmpp_to_hostname=self.xmpp_to_hostname,
            client_auth_credentials=self.client_auth_credentials,
            http_tunneling_settings=self.http_tunneling_settings
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
            self,
            max_threads: int = _DEFAULT_MAX_THREADS,
            network_timeout: Optional[int] = None
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
