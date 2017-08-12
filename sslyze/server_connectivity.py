# -*- coding: utf-8 -*-
"""Core classes to ensure that the servers to be scanned are actually online and reachable.
"""
from __future__ import absolute_import
from __future__ import unicode_literals

import socket

from enum import Enum
from typing import Iterable
from typing import List
from typing import Optional
from nassl.ssl_client import ClientCertificateRequested, OpenSslVersionEnum

from sslyze.ssl_settings import TlsWrappedProtocolEnum, ClientAuthenticationCredentials, HttpConnectTunnelingSettings
from typing import Text
from typing import Tuple
from sslyze.utils.ssl_connection import StartTLSError, ProxyError, SSLConnection, SMTPConnection, XMPPConnection, \
    XMPPServerConnection, POP3Connection, IMAPConnection, FTPConnection, LDAPConnection, RDPConnection, \
    PostgresConnection, HTTPSConnection
from sslyze.utils.thread_pool import ThreadPool


class ServerConnectivityError(ValueError):
    def __init__(self, error_msg):
        # type: (Text) -> None
        self.error_msg = error_msg


class ClientAuthenticationServerConfigurationEnum(Enum):
    """Whether the server asked for client authentication.
    """
    DISABLED = 1
    OPTIONAL = 2
    REQUIRED = 3


class ServerConnectivityInfo(object):
    """An object encapsulating all the settings (hostname, port, SSL version, etc.) needed to successfully connect to a
    specific SSL/TLS server.
    """

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

    CONNECTIVITY_ERROR_NAME_NOT_RESOLVED = 'Could not resolve {hostname}'
    CONNECTIVITY_ERROR_TIMEOUT = 'Could not connect (timeout)'
    CONNECTIVITY_ERROR_REJECTED = 'Connection rejected'
    CONNECTIVITY_ERROR_HANDSHAKE_ERROR = 'Could not complete an SSL handshake'


    def __init__(
            self,
            hostname,                                               # type: Text
            port=None,                                              # type: Optional[int]
            ip_address=None,                                        # type: Optional[Text]
            tls_wrapped_protocol=TlsWrappedProtocolEnum.PLAIN_TLS,  # type: Optional[TlsWrappedProtocolEnum]
            tls_server_name_indication=None,                        # type: Optional[Text]
            xmpp_to_hostname=None,                                  # type: Optional[Text]
            client_auth_credentials=None,                           # type: Optional[ClientAuthenticationCredentials]
            http_tunneling_settings=None                            # type: Optional[HttpConnectTunnelingSettings]
            ):
        # type: (...) -> None
        """Constructor to specify how to connect to a server to be scanned.

        Most arguments are optional but can be supplied in order to be more specific about the server's configuration.

        After initializing a ServerConnectivityInfo, the `test_connectivity_to_server()` method must be called next to
        ensure that the server is actually reachable.

        Args:
            hostname (Text): The server's hostname.
            port (Optional[int]): The server's TLS port number. If not supplied, the default port number for the
                specified `tls_wrapped_protocol` will be used.
            ip_address (Optional[Text]): The server's IP address. If not supplied, a DNS lookup for the specified
                `hostname` will be performed. If `http_tunneling_settings` is specified, `ip_address` cannot be supplied
                as the HTTP proxy will be responsible for looking up and connecting to the server to be scanned.
            tls_wrapped_protocol (Optional[TlsWrappedProtocolEnum]): The protocol wrapped in TLS that the server
                expects. It allows sslyze to figure out how to establish a (Start)TLS connection to the server and what
                kind of "hello" message (SMTP, XMPP, etc.) to send to the server after the handshake was completed. If
                not supplied, standard TLS will be used.
            tls_server_name_indication (Optional[Text]): The hostname to set within the Server Name Indication TLS
                extension. If not supplied, the specified `hostname` will be used.
            xmpp_to_hostname (Optional[Text]): The hostname to set within the `to` attribute of the XMPP stream. If not
                supplied, the specified `hostname` will be used. Should only be set if the supplied
                `tls_wrapped_protocol` is an XMPP protocol.
            client_auth_credentials (Optional[ClientAuthenticationCredentials]): The client certificate and private key
                needed to perform mutual authentication with the server. If not supplied, sslyze will attempt to connect
                to the server without performing mutual authentication.
            http_tunneling_settings (Optional[HttpConnectTunnelingSettings]): The HTTP proxy configuration to use in
                order to tunnel the scans through a proxy. If not supplied, sslyze will run the scans by directly
                connecting to the server.

        Raises:
            ServerConnectivityError: If a DNS lookup was attempted and failed.
            ValueError: If `xmpp_to_hostname` was specified for a non-XMPP protocol.
            ValueError: If both `ip_address` and `http_tunneling_settings` were supplied.
        """
        # Store the hostname in ACE format in the case the domain name is unicode
        self.hostname = hostname.encode('idna').decode('utf-8')
        self.tls_wrapped_protocol = tls_wrapped_protocol

        self.port = port
        if not self.port:
            self.port = self.TLS_DEFAULT_PORTS[tls_wrapped_protocol]

        if ip_address and http_tunneling_settings:
            raise ValueError('Cannot specify both ip_address and http_tunneling_settings.')

        elif not ip_address and not http_tunneling_settings:
            # Do a DNS lookup
            try:
                addr_infos = socket.getaddrinfo(self.hostname, self.port, socket.AF_UNSPEC, socket.IPPROTO_IP)
                family, socktype, proto, canonname, sockaddr = addr_infos[0]

                # Works for both IPv4 and IPv6
                self.ip_address = sockaddr[0]

            except (socket.gaierror, IndexError):
                raise ServerConnectivityError(self.CONNECTIVITY_ERROR_NAME_NOT_RESOLVED.format(hostname=self.hostname))

        else:
            # An IP address was specified or the scan will go through a proxy
            self.ip_address = ip_address

        # Use the hostname as the default SNI
        self.tls_server_name_indication = tls_server_name_indication if tls_server_name_indication else self.hostname

        self.xmpp_to_hostname = xmpp_to_hostname
        if self.xmpp_to_hostname and self.tls_wrapped_protocol not in [TlsWrappedProtocolEnum.STARTTLS_XMPP,
                                                                       TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER]:
            raise ValueError('Can only specify xmpp_to for the XMPP StartTLS protocol.')

        self.client_auth_credentials = client_auth_credentials
        self.http_tunneling_settings = http_tunneling_settings

        # Set after actually testing the connectivity
        self.highest_ssl_version_supported = None
        self.ssl_cipher_supported = None
        self.client_auth_requirement = None


    def test_connectivity_to_server(self, network_timeout=None):
        # type: (Optional[int]) -> None
        """Attempts to perform a full SSL/TLS handshake with the server.

        This method will ensure that the server can be reached, and will also identify one SSL/TLS version and one
        cipher suite supported by the server. If the connectivity test is successful, the `ServerConnectivityInfo`
        object is then ready to be passed to a `SynchronousScanner` or `ConcurrentScanner` in order to run scan commands
        on the server.

        Args:
            network_timeout (Optional[int]): Network timeout value in seconds passed to the underlying socket.

        Raises:
            ServerConnectivityError: If the server was not reachable or an SSL/TLS handshake could not be completed.
        """
        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.DISABLED
        ssl_connection = self.get_preconfigured_ssl_connection(override_ssl_version=OpenSslVersionEnum.SSLV23)

        # First only try a socket connection
        try:
            ssl_connection.do_pre_handshake(network_timeout=network_timeout)

        # Socket errors
        except socket.timeout:  # Host is down
            raise ServerConnectivityError(self.CONNECTIVITY_ERROR_TIMEOUT)
        except socket.error:  # Connection Refused
            raise ServerConnectivityError(self.CONNECTIVITY_ERROR_REJECTED)

        # StartTLS errors
        except StartTLSError as e:
            raise ServerConnectivityError(e[0])

        # Proxy errors
        except ProxyError as e:
            raise ServerConnectivityError(e[0])

        # Other errors
        except Exception as e:
            raise ServerConnectivityError('{0}: {1}'.format(str(type(e).__name__), e))

        finally:
            ssl_connection.close()

        # Then try to complete an SSL handshake to figure out the SSL version and cipher supported by the server
        ssl_version_supported = None
        ssl_cipher_supported = None

        for ssl_version in [OpenSslVersionEnum.TLSV1_2, OpenSslVersionEnum.TLSV1_1, OpenSslVersionEnum.TLSV1,
                            OpenSslVersionEnum.SSLV3, OpenSslVersionEnum.SSLV23]:
            # First try the default cipher list, and then all ciphers
            for cipher_list in [SSLConnection.DEFAULT_SSL_CIPHER_LIST, 'ALL:COMPLEMENTOFALL']:
                ssl_connection = self.get_preconfigured_ssl_connection(override_ssl_version=ssl_version,
                                                                       should_ignore_client_auth=False)
                ssl_connection.ssl_client.set_cipher_list(cipher_list)
                try:
                    # Only do one attempt when testing connectivity
                    ssl_connection.connect(network_timeout=network_timeout, network_max_retries=0)
                    ssl_version_supported = ssl_version
                    ssl_cipher_supported = ssl_connection.ssl_client.get_current_cipher_name()
                    break
                except ClientCertificateRequested:
                    # Connection successful but the servers wants a client certificate which wasn't supplied to sslyze
                    # Store the SSL version and cipher list that is supported
                    ssl_version_supported = ssl_version
                    ssl_cipher_supported = cipher_list

                    # Try a new connection to see if client authentication is optional
                    ssl_connection_auth = self.get_preconfigured_ssl_connection(override_ssl_version=ssl_version,
                                                                                should_ignore_client_auth=True)
                    ssl_connection_auth.ssl_client.set_cipher_list(cipher_list)
                    try:
                        ssl_connection_auth.connect(network_max_retries=0)
                        ssl_cipher_supported = ssl_connection_auth.ssl_client.get_current_cipher_name()
                        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.OPTIONAL
                    except:
                        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.REQUIRED
                    finally:
                        ssl_connection.close()

                except:
                    # Could not complete a handshake with this server
                    pass
                finally:
                    ssl_connection.close()

            if ssl_cipher_supported:
                # A handshake was successful
                break

        if ssl_version_supported is None or ssl_cipher_supported is None:
            raise ServerConnectivityError(self.CONNECTIVITY_ERROR_HANDSHAKE_ERROR)

        self.highest_ssl_version_supported = ssl_version_supported
        self.ssl_cipher_supported = ssl_cipher_supported
        self.client_auth_requirement = client_auth_requirement


    def get_preconfigured_ssl_connection(self, override_ssl_version=None, ssl_verify_locations=None,
                                         should_ignore_client_auth=None):
        # type: (Optional[int], Optional[bool], Optional[bool]) -> SSLConnection
        """Get an SSLConnection instance with the right SSL configuration for successfully connecting to the server.

        Used by all plugins to connect to the server and run scans.
        """
        if self.highest_ssl_version_supported is None and override_ssl_version is None:
            raise ValueError('Cannot return an SSLConnection without testing connectivity; '
                             'call test_connectivity_to_server() first')

        if should_ignore_client_auth is None:
            # Ignore client auth requests if the server allows optional TLS client authentication
            # If the server requires client authentication, do not ignore the request so that the right exceptions get
            # thrown within the plugins, providing a better output
            should_ignore_client_auth = False \
                if self.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.REQUIRED \
                else True

        # Create the right SSLConnection object
        ssl_version = override_ssl_version if override_ssl_version is not None else self.highest_ssl_version_supported
        ssl_connection = self.TLS_CONNECTION_CLASSES[self.tls_wrapped_protocol](
            self.hostname, self.ip_address, self.port, ssl_version, ssl_verify_locations=ssl_verify_locations,
            client_auth_creds=self.client_auth_credentials,
            should_ignore_client_auth=should_ignore_client_auth
        )

        # Add XMPP configuration
        if self.tls_wrapped_protocol in [TlsWrappedProtocolEnum.STARTTLS_XMPP,
                                         TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER] and self.xmpp_to_hostname:
            ssl_connection.set_xmpp_to(self.xmpp_to_hostname)

        # Add HTTP tunneling configuration
        if self.http_tunneling_settings:
            ssl_connection.enable_http_connect_tunneling(self.http_tunneling_settings.hostname,
                                                         self.http_tunneling_settings.port,
                                                         self.http_tunneling_settings.basic_auth_user,
                                                         self.http_tunneling_settings.basic_auth_password)

        # Add Server Name Indication
        if ssl_version != OpenSslVersionEnum.SSLV2:
            ssl_connection.ssl_client.set_tlsext_host_name(self.tls_server_name_indication)

        # Add well-known supported cipher suite
        if self.ssl_cipher_supported and override_ssl_version is None:
            ssl_connection.ssl_client.set_cipher_list(self.ssl_cipher_supported)

        return ssl_connection


class ServersConnectivityTester(object):
    """Utility class to run servers connectivity testing on a list of ServerConnectivityInfo using a thread pool.
    """

    _DEFAULT_MAX_THREADS = 50

    def __init__(self, tentative_server_info_list):
        # type: (List[ServerConnectivityInfo]) -> None
        # Use a thread pool to connect to each server
        self._thread_pool = ThreadPool()
        self._server_info_list = tentative_server_info_list

    def start_connectivity_testing(self, max_threads=_DEFAULT_MAX_THREADS, network_timeout=None):
        # type: (Optional[int], Optional[int]) -> None
        for tentative_server_info in self._server_info_list:
            self._thread_pool.add_job((tentative_server_info.test_connectivity_to_server, [network_timeout]))
        nb_threads = min(len(self._server_info_list), max_threads)
        self._thread_pool.start(nb_threads)

    def get_reachable_servers(self):
        # type: () -> Iterable[ServerConnectivityInfo]
        for (job, _) in self._thread_pool.get_result():
            test_connectivity_to_server_method, _ = job
            server_info = test_connectivity_to_server_method.__self__
            yield server_info

    def get_invalid_servers(self):
        # type: () -> Iterable[Tuple[ServerConnectivityInfo, Exception]]
        for (job, exception) in self._thread_pool.get_error():
            test_connectivity_to_server_method, _ = job
            server_info = test_connectivity_to_server_method.__self__
            yield (server_info, exception)
