#!/usr/bin/env python2.7
# -------------------------------------------------------------------------------
# Name:         ServersConnectivityTester.py
# Purpose:      Initial checks to figure out which servers supplied by the
#               user are actually reachable.
#
# Author:       alban
#
# Copyright:    2013 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
# -------------------------------------------------------------------------------
import os
import socket
from base64 import b64encode
from urllib import quote
from urlparse import urlparse
from ThreadPool import ThreadPool
from nassl import SSLV23, SSLV3, TLSV1, TLSV1_2, SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1, SSLV2
from SSLyzeSSLConnection import StartTLSError, ProxyError, SSLConnection, SMTPConnection, \
    XMPPConnection, XMPPServerConnection, POP3Connection, IMAPConnection, FTPConnection, LDAPConnection, RDPConnection, \
    PostgresConnection
from nassl.SslClient import SslClient


class ServerConnectivityError(ValueError):
    def __init__(self, error_msg):
        self.error_msg = error_msg


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


# TODO: Rename this and add HTTP
class StartTlsProtocolEnum(object):
    NO_STARTTLS = 1  # Standard TLS connection
    SMTP = 2
    XMPP = 3
    XMPP_SERVER = 4
    FTP = 5
    POP3 = 6
    LDAP = 7
    IMAP = 8
    RDP = 9
    POSTGRES = 10


class ClientAuthenticationCredentials(object):
    """Everything needed to perform client authentication with an SSL server.
    """

    def __init__(self, client_certificate_chain_path, client_key_path, client_key_type=SSL_FILETYPE_PEM,
                 client_key_password=''):

        self.client_certificate_chain_path = client_certificate_chain_path
        if not os.path.isfile(self.client_certificate_chain_path):
            raise ValueError('Could not open the client certificate file')

        self.client_key_path = client_key_path
        if not os.path.isfile(self.client_key_path):
            raise ValueError('Could not open the client private key file')

        self.client_key_password = client_key_password

        self.client_key_type = client_key_type
        if self.client_key_type not in [SSL_FILETYPE_ASN1, SSL_FILETYPE_PEM]:
            raise ValueError('Invalid certificate format specified')

        # Try to load the cert and key in OpenSSL; will raise an exception if something is wrong
        SslClient(client_certchain_file=self.client_certificate_chain_path, client_key_file=self.client_key_path,
                  client_key_type=self.client_key_type, client_key_password=self.client_key_password)


class HttpConnectTunnelingSettings(object):
    """Information needed to tunnel SSL/TLS traffic through an HTTP Connect Proxy.
    """

    def __init__(self, hostname, port, basic_auth_user=None, basic_auth_password=None):
        self.hostname = hostname
        self.port = port
        self.basic_auth_user = basic_auth_user
        self.basic_auth_password = basic_auth_password


    @classmethod
    def from_url(cls, proxy_url):
        parsed_url = urlparse(proxy_url)

        if not parsed_url.netloc or not parsed_url.hostname:
            raise ValueError('Invalid Proxy URL.')

        if parsed_url.scheme == 'http':
           default_port = 80
        elif parsed_url.scheme == 'https':
           default_port = 443
        else:
            raise ValueError('Invalid URL scheme')

        port = parsed_url.port if parsed_url.port else default_port
        return cls(parsed_url.hostname, port, parsed_url.username, parsed_url.password)


    def get_basic_auth_header(self):
        header = ''
        if self.basic_auth_user is not None:
            header = b64encode('{0}:{1}'.format(quote(self.basic_auth_user), quote(self.basic_auth_password)))
        return header


class ServerConnectivityInfo(object):
    """All settings (hostname, port, SSL version, etc.) needed to successfully connect to a specific SSL server."""

    STARTTLS_DEFAULT_PORTS = {
        StartTlsProtocolEnum.NO_STARTTLS: 443,
        StartTlsProtocolEnum.SMTP: 25,
        StartTlsProtocolEnum.XMPP: 5222,
        StartTlsProtocolEnum.XMPP_SERVER: 5269,
        StartTlsProtocolEnum.FTP: 21,
        StartTlsProtocolEnum.POP3: 110,
        StartTlsProtocolEnum.LDAP: 389,
        StartTlsProtocolEnum.IMAP: 143,
        StartTlsProtocolEnum.RDP: 3389,
        StartTlsProtocolEnum.POSTGRES: 5432
    }

    STARTTLS_CONNECTION_CLASSES = {
        StartTlsProtocolEnum.NO_STARTTLS: SSLConnection,
        StartTlsProtocolEnum.SMTP: SMTPConnection,
        StartTlsProtocolEnum.XMPP: XMPPConnection,
        StartTlsProtocolEnum.XMPP_SERVER: XMPPServerConnection,
        StartTlsProtocolEnum.POP3: POP3Connection,
        StartTlsProtocolEnum.IMAP: IMAPConnection,
        StartTlsProtocolEnum.FTP: FTPConnection,
        StartTlsProtocolEnum.LDAP: LDAPConnection,
        StartTlsProtocolEnum.RDP: RDPConnection,
        StartTlsProtocolEnum.POSTGRES: PostgresConnection,
    }

    CONNECTIVITY_ERROR_NAME_NOT_RESOLVED = 'Could not resolve {hostname}'
    CONNECTIVITY_ERROR_TIMEOUT = 'Could not connect (timeout)'
    CONNECTIVITY_ERROR_REJECTED = 'Connection rejected'
    CONNECTIVITY_ERROR_HANDSHAKE_ERROR = 'Could not complete an SSL handshake'


    def __init__(self, hostname, port=None, ip_address=None, starttls_protocol=StartTlsProtocolEnum.NO_STARTTLS,
                 tls_server_name_indication=None, xmpp_to_hostname=None, client_auth_credentials=None,
                 http_tunneling_settings=None):

        self.hostname = hostname
        self.starttls_protocol = starttls_protocol

        self.port = port
        if not self.port:
            self.port = self.STARTTLS_DEFAULT_PORTS[starttls_protocol]

        self.ip_address = ip_address
        if not self.ip_address:
            try:
                self.ip_address = socket.gethostbyname(self.hostname)
            except socket.gaierror:
                raise ServerConnectivityError(self.CONNECTIVITY_ERROR_NAME_NOT_RESOLVED.format(hostname=self.hostname))

        self.tls_server_name_indication = tls_server_name_indication
        if not self.tls_server_name_indication:
            # Use the hostname as the default SNI
            self.tls_server_name_indication = self.hostname

        self.xmpp_to_hostname = xmpp_to_hostname
        if self.xmpp_to_hostname and self.starttls_protocol not in [StartTlsProtocolEnum.XMPP,
                                                                    StartTlsProtocolEnum.XMPP_SERVER]:
            raise ValueError('Can only specify xmpp_to for the XMPP StartTLS protocol.')

        self.client_auth_credentials = client_auth_credentials
        self.http_tunneling_settings = http_tunneling_settings

        # Set after actually testing the connectivity
        self.ssl_version_supported = None
        self.ssl_cipher_supported = None


    @classmethod
    def from_command_line(cls, server_string, starttls_protocol=StartTlsProtocolEnum.NO_STARTTLS,
                          tls_server_name_indication=None, xmpp_to_hostname=None,
                          client_auth_credentials=None, http_tunneling_settings=None):
        """Constructor that parses a single server string from a command line used to launch SSLyze and returns the
        corresponding ServerConnectivityInfo.
        """
        # Will raise a ValueError if the server string is not properly formatted
        (hostname, ip_address, port) = CommandLineServerStringParser.parse_server_string(server_string)
        return cls(hostname=hostname,
                   port=port,
                   ip_address=ip_address,
                   starttls_protocol=starttls_protocol,
                   tls_server_name_indication=tls_server_name_indication,
                   xmpp_to_hostname=xmpp_to_hostname,
                   client_auth_credentials=client_auth_credentials,
                   http_tunneling_settings=http_tunneling_settings)


    def test_connectivity_to_server(self):
        """Attempts to perform a full SSL handshake with the server in order to identify one SSL version and cipher
        suite supported by the server."""

        ssl_connection = self.get_preconfigured_ssl_connection(override_ssl_version=SSLV23)

        # First only try a socket connection
        try:
            ssl_connection.do_pre_handshake()

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
            raise ServerConnectivityError('{0}: {1}'.format(str(type(e).__name__), e[0]))

        finally:
            ssl_connection.close()

        # Then try to complete an SSL handshake to figure out the SSL version and cipher supported by the server
        ssl_version_supported = None
        ssl_cipher_supported = None
        for ssl_version in [TLSV1, SSLV23, SSLV3, TLSV1_2]:
            # Try with the default cipher list
            ssl_connection = self.get_preconfigured_ssl_connection(override_ssl_version=ssl_version)
            try:
                # Only do one attempt when testing connectivity
                ssl_connection.connect(network_max_retries=0)
                ssl_version_supported = ssl_version
                ssl_cipher_supported = ssl_connection.get_current_cipher_name()
                break
            except:
                # Default cipher list failed; try one more time with all cipher suites enabled
                ssl_connection_all_ciphers = self.get_preconfigured_ssl_connection(override_ssl_version=ssl_version)
                ssl_connection_all_ciphers.set_cipher_list('ALL:COMPLEMENTOFALL')
                try:
                    ssl_connection_all_ciphers.connect(network_max_retries=0)
                    ssl_version_supported = ssl_version
                    ssl_cipher_supported = ssl_connection_all_ciphers.get_current_cipher_name()
                    break
                except:
                    # Could not complete a handshake with this server
                    pass
                finally:
                    ssl_connection_all_ciphers.close()
            finally:
                ssl_connection.close()

        if ssl_version_supported is None or ssl_cipher_supported is None:
            raise ServerConnectivityError(self.CONNECTIVITY_ERROR_HANDSHAKE_ERROR)

        self.ssl_version_supported = ssl_version_supported
        self.ssl_cipher_supported = ssl_cipher_supported


    def get_preconfigured_ssl_connection(self, override_ssl_version=None, ssl_verify_locations=None):
        """Returns an SSLConnection with the right configuration for successfully establishing an SSL connection to the
        server. """
        if self.ssl_version_supported is None and override_ssl_version is None:
            raise ValueError('Cannot return an SSLConnection without testing connectivity; '
                             'call test_connectivity_to_server() first')

        # Create the right SSLConnection object
        ssl_version = override_ssl_version if override_ssl_version is not None else self.ssl_version_supported
        ssl_connection = self.STARTTLS_CONNECTION_CLASSES[self.starttls_protocol](
                self.hostname, self.ip_address, self.port, ssl_version, ssl_verify_locations=ssl_verify_locations
        )

        # Add XMPP configuration
        if self.starttls_protocol in [StartTlsProtocolEnum.XMPP,
                                      StartTlsProtocolEnum.XMPP_SERVER] and self.xmpp_to_hostname:
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

        return ssl_connection


class ServersConnectivityTester(object):
    """Utility class to connect to a list of servers and return a list of online and offline servers.
    """

    DEFAULT_MAX_THREADS = 50

    ERR_TIMEOUT = 'Could not connect (timeout)'
    ERR_NAME_NOT_RESOLVED = 'Could not resolve hostname'
    ERR_REJECTED = 'Connection rejected'

    def __init__(self, tentative_server_info_list):
        # Use a thread pool to connect to each server
        self._thread_pool = ThreadPool()
        self._server_info_list = tentative_server_info_list


    def start_connectivity_testing(self, max_threads=DEFAULT_MAX_THREADS):
        """Parses the each server string and tests connectivity with the server.
        """
        for tentative_server_info in self._server_info_list:
            self._thread_pool.add_job((tentative_server_info.test_connectivity_to_server, []))
        nb_threads = min(len(self._server_info_list), max_threads)
        self._thread_pool.start(nb_threads)


    def get_reachable_servers(self):
        # Return valid targets
        for (job, _) in self._thread_pool.get_result():
            test_connectivity_to_server_method, _ = job
            server_info = test_connectivity_to_server_method.__self__
            yield server_info


    def get_invalid_servers(self):
        # Return invalid targets
        for (job, exception) in self._thread_pool.get_error():
            test_connectivity_to_server_method, _ = job
            server_info = test_connectivity_to_server_method.__self__
            yield (server_info, exception)
