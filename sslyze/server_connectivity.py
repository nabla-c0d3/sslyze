# -*- coding: utf-8 -*-
"""Utility classes to ensure that the servers to be scanned are actually reachable.
"""

import socket

from nassl import SSLV23, SSLV3, TLSV1, TLSV1_2, SSLV2, TLSV1_1
from nassl.ssl_client import ClientCertificateRequested

from sslyze.ssl_settings import TlsWrappedProtocolEnum
from utils.ssl_connection import StartTLSError, ProxyError, SSLConnection, SMTPConnection, XMPPConnection, \
    XMPPServerConnection, POP3Connection, IMAPConnection, FTPConnection, LDAPConnection, RDPConnection, \
    PostgresConnection, HTTPSConnection
from utils.thread_pool import ThreadPool


class ServerConnectivityError(ValueError):
    def __init__(self, error_msg):
        self.error_msg = error_msg


class ClientAuthenticationServerConfigurationEnum(object):
    """Whether the server asked for client authentication.
    """
    DISABLED = 1
    OPTIONAL = 2
    REQUIRED = 3


class ServerConnectivityInfo(object):
    """All settings (hostname, port, SSL version, etc.) needed to successfully connect to a specific SSL server.

    After initializing a ServerConnectivityInfo, the test_connectivity_to_server() method must be called next to
    ensure that the server is actually reachable.
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

    CONNECTIVITY_ERROR_NAME_NOT_RESOLVED = u'Could not resolve {hostname}'
    CONNECTIVITY_ERROR_TIMEOUT = 'Could not connect (timeout)'
    CONNECTIVITY_ERROR_REJECTED = 'Connection rejected'
    CONNECTIVITY_ERROR_HANDSHAKE_ERROR = 'Could not complete an SSL handshake'


    def __init__(self, hostname, port=None, ip_address=None, tls_wrapped_protocol=TlsWrappedProtocolEnum.PLAIN_TLS,
                 tls_server_name_indication=None, xmpp_to_hostname=None, client_auth_credentials=None,
                 http_tunneling_settings=None):
        """Constructor to specify how to connect to a server to be scanned.

        Most arguments are optional but can be supplied in order to be more specific about the server's configuration.

        Args:
            hostname (unicode): The server's hostname.
            port (int): The server's TLS port number. If not supplied, the default port number for the specified
                `tls_wrapped_protocol` will be used.
            ip_address (Optional[str]): The server's IP address. If not supplied, a DNS lookup for the specified
                `hostname` will be performed. If `http_tunneling_settings` is specified, `ip_address` cannot be supplied
                as the HTTP proxy will be responsible for looking up and connecting to the server to be scanned.
            tls_wrapped_protocol (Optional[TlsWrappedProtocolEnum]): The protocol wrapped in TLS that the server
                expects. It allows sslyze to figure out how to establish a (Start)TLS connection to the server and what
                kind of "hello" message (SMTP, XMPP, etc.) to send to the server after the handshake was completed. If
                not supplied, standard TLS will be used.
            tls_server_name_indication (Optional[str]): The hostname to set within the Server Name Indication TLS
                extension. If not supplied, the specified `hostname` will be used.
            xmpp_to_hostname (Optional[str]): The hostname to set within the `to` attribute of the XMPP stream. If not
                supplied, the specified `hostname` will be used. Should only be set if the supplied
                `tls_wrapped_protocol` is an XMPP protocol.
            client_auth_credentials (Optional[ClientAuthenticationCredentials]): The client certificate and private key
                needed to perform mutual authentication with the server. If not supplied, sslyze will attempt to connect
                to the server without performing mutual authentication.
            http_tunneling_settings (Optional[HttpConnectTunnelingSettings]): The HTTP proxy configuration to use in
                order to tunnel the scans through a proxy. If not supplied, sslyze will run the scans by directly
                connecting to the server.

        Returns:
            ServerConnectivityInfo: An object representing all the information needed to connect to a specific server.
            This information must be validated by calling the `test_connectivity_to_server()` method.

        Raises:
            ServerConnectivityError: If a DNS lookup was attempted and failed.
            ValueError: If `xmpp_to_hostname` was specified for a non-XMPP protocol.
            ValueError: If both `ip_address` and `http_tunneling_settings` were supplied.
        """
        # Store the hostname in ACE format in the case the domain name is unicode
        self.hostname = hostname.encode('idna')
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


    @classmethod
    def from_command_line(cls, server_string, tls_wrapped_protocol=TlsWrappedProtocolEnum.PLAIN_TLS,
                          tls_server_name_indication=None, xmpp_to_hostname=None,
                          client_auth_credentials=None, http_tunneling_settings=None):
        """Constructor that parses a single server string from a command line used to launch SSLyze and returns the
        corresponding ServerConnectivityInfo.
        """
        # Will raise a ValueError if the server string is not properly formatted
        hostname, ip_address, port = CommandLineServerStringParser.parse_server_string(server_string)
        server_info = cls(hostname=hostname,
                         port=port,
                         ip_address=ip_address,
                         tls_wrapped_protocol=tls_wrapped_protocol,
                         tls_server_name_indication=tls_server_name_indication,
                         xmpp_to_hostname=xmpp_to_hostname,
                         client_auth_credentials=client_auth_credentials,
                         http_tunneling_settings=http_tunneling_settings)
        # Keep the original server string to display it in the CLI output if there was a connection error
        server_info.server_string = server_string
        return server_info


    def test_connectivity_to_server(self, network_timeout=None):
        """Attempts to perform a full SSL handshake with the server in order to identify one SSL version and cipher
        suite supported by the server.

        Args:
            network_timeout (int): Network timeout value in seconds passed to the underlying socket.
        """
        client_auth_requirement = ClientAuthenticationServerConfigurationEnum.DISABLED
        ssl_connection = self.get_preconfigured_ssl_connection(override_ssl_version=SSLV23)

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
            raise ServerConnectivityError(u'{0}: {1}'.format(str(type(e).__name__), e[0]))

        finally:
            ssl_connection.close()

        # Then try to complete an SSL handshake to figure out the SSL version and cipher supported by the server
        ssl_version_supported = None
        ssl_cipher_supported = None

        for ssl_version in [TLSV1_2, TLSV1_1, TLSV1, SSLV3, SSLV23]:
            # First try the default cipher list, and then all ciphers
            for cipher_list in [SSLConnection.DEFAULT_SSL_CIPHER_LIST, 'ALL:COMPLEMENTOFALL']:
                ssl_connection = self.get_preconfigured_ssl_connection(override_ssl_version=ssl_version,
                                                                       should_ignore_client_auth=False)
                ssl_connection.set_cipher_list(cipher_list)
                try:
                    # Only do one attempt when testing connectivity
                    ssl_connection.connect(network_timeout=network_timeout, network_max_retries=0)
                    ssl_version_supported = ssl_version
                    ssl_cipher_supported = ssl_connection.get_current_cipher_name()
                    break
                except ClientCertificateRequested:
                    # Connection successful but the servers wants a client certificate which wasn't supplied to sslyze
                    # Store the SSL version and cipher list that is supported
                    ssl_version_supported = ssl_version
                    ssl_cipher_supported = cipher_list

                    # Try a new connection to see if client authentication is optional
                    ssl_connection_auth = self.get_preconfigured_ssl_connection(override_ssl_version=ssl_version,
                                                                                should_ignore_client_auth=True)
                    ssl_connection_auth.set_cipher_list(cipher_list)
                    try:
                        ssl_connection_auth.connect(network_max_retries=0)
                        ssl_cipher_supported = ssl_connection_auth.get_current_cipher_name()
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
        """Returns an SSLConnection instance with the right configuration for successfully establishing an SSL
        connection to the server. Used by all plugins to connect to the server and run scans.
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
        if ssl_version != SSLV2:
            ssl_connection.set_tlsext_host_name(self.tls_server_name_indication)

        # Add well-known supported cipher suite
        if self.ssl_cipher_supported and override_ssl_version is None:
            ssl_connection.set_cipher_list(self.ssl_cipher_supported)

        return ssl_connection


class ServersConnectivityTester(object):
    """Utility class to run servers connectivity testing on a list of ServerConnectivityInfo using a thread pool.
    """

    DEFAULT_MAX_THREADS = 50

    def __init__(self, tentative_server_info_list):
        # Use a thread pool to connect to each server
        self._thread_pool = ThreadPool()
        self._server_info_list = tentative_server_info_list

    def start_connectivity_testing(self, max_threads=DEFAULT_MAX_THREADS, network_timeout=None):
        for tentative_server_info in self._server_info_list:
            self._thread_pool.add_job((tentative_server_info.test_connectivity_to_server, [network_timeout]))
        nb_threads = min(len(self._server_info_list), max_threads)
        self._thread_pool.start(nb_threads)

    def get_reachable_servers(self):
        for (job, _) in self._thread_pool.get_result():
            test_connectivity_to_server_method, _ = job
            server_info = test_connectivity_to_server_method.__self__
            yield server_info

    def get_invalid_servers(self):
        for (job, exception) in self._thread_pool.get_error():
            test_connectivity_to_server_method, _ = job
            server_info = test_connectivity_to_server_method.__self__
            yield (server_info, exception)



class CommandLineServerStringParser(object):
    """Utility class to parse a 'host:port{ip}' string taken from the command line into a valid (host,ip, port) tuple.
    Supports IPV6 addresses.
    """

    SERVER_STRING_ERROR_BAD_PORT = 'Not a valid host:port'
    SERVER_STRING_ERROR_NO_IPV6 = 'IPv6 is not supported on this platform'

    @classmethod
    def parse_server_string(cls, server_str):
        # Extract ip from target
        if '{' in server_str and '}' in server_str:
            raw_target = server_str.split('{')
            raw_ip = raw_target[1]

            ip = raw_ip.replace('}', '')

            # Clean the target
            server_str = raw_target[0]
        else:
            ip = None

        # Look for ipv6 hint in target
        if '[' in server_str:
            (host, port) = cls._parse_ipv6_server_string(server_str)
        else:
            # Look for ipv6 hint in the ip
            if ip is not None and '[' in ip:
                (ip, port) = cls._parse_ipv6_server_string(ip)

            # Fallback to ipv4
            (host, port) = cls._parse_ipv4_server_string(server_str)

        return host, ip, port

    @classmethod
    def _parse_ipv4_server_string(cls, server_str):

        if ':' in server_str:
            host = (server_str.split(':'))[0]  # hostname or ipv4 address
            try:
                port = int((server_str.split(':'))[1])
            except:  # Port is not an int
                raise ServerConnectivityError(cls.SERVER_STRING_ERROR_BAD_PORT)
        else:
            host = server_str
            port = None

        return host, port

    @classmethod
    def _parse_ipv6_server_string(cls, server_str):

        if not socket.has_ipv6:
            raise ServerConnectivityError(cls.SERVER_STRING_ERROR_NO_IPV6)

        port = None
        target_split = (server_str.split(']'))
        ipv6_addr = target_split[0].split('[')[1]
        if ':' in target_split[1]:  # port was specified
            try:
                port = int(target_split[1].rsplit(':')[1])
            except:  # Port is not an int
                raise ServerConnectivityError(cls.SERVER_STRING_ERROR_BAD_PORT)
        return ipv6_addr, port

