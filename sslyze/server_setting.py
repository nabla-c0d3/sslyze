import socket
from base64 import b64encode
from enum import Enum
from pathlib import Path
from typing import Optional

from urllib.parse import quote

from dataclasses import dataclass
from urllib.parse import urlparse

from nassl.ssl_client import OpenSslFileTypeEnum, SslClient

from sslyze.connection_helpers.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum
from sslyze.errors import InvalidServerNetworkConfigurationError, ServerHostnameCouldNotBeResolved


@dataclass(frozen=True)
class HttpProxySettings:
    hostname: str
    port: int

    basic_auth_user: Optional[str] = None
    basic_auth_password: Optional[str] = None

    @classmethod
    def from_url(cls, proxy_url: str) -> "HttpProxySettings":
        parsed_url = urlparse(proxy_url)
        if not parsed_url.netloc or not parsed_url.hostname:
            raise ValueError("Invalid Proxy URL")

        if parsed_url.scheme == "http":
            default_port = 80
        elif parsed_url.scheme == "https":
            default_port = 443
        else:
            raise ValueError("Invalid URL scheme")

        port = parsed_url.port if parsed_url.port else default_port
        return cls(parsed_url.hostname, port, parsed_url.username, parsed_url.password)

    @property
    def proxy_authorization_header(self) -> Optional[str]:
        if not self.basic_auth_user:
            return None
        if not self.basic_auth_password:
            raise ValueError("No password configured for Basic Auth")

        basic_auth_token = b64encode(f"{quote(self.basic_auth_user)}:{quote(self.basic_auth_password)}".encode("utf-8"))
        return basic_auth_token.decode("utf-8")


class ConnectionTypeEnum(str, Enum):
    DIRECT = "DIRECT"
    VIA_HTTP_PROXY = "VIA_HTTP_PROXY"


@dataclass(frozen=True)
class ServerNetworkLocation:
    """All the information needed to connect to a server.

    Attributes:
        hostname: The server's hostname.
        port: The server's TLS port number.
        connection_type: How sslyze should connect to the server: either directly, or via an HTTP proxy.
        ip_address: The server's IP address; only set if sslyze is connecting directly to the server. If no IP address
            is supplied and connection_type is set to DIRECT, sslyze will automatically lookup one IP address for the
            supplied hostname.
        http_proxy_settings: The HTTP proxy configuration to use in order to tunnel the scans through a proxy; only set
            if sslyze is connecting to the server via an HTTP proxy. The proxy will be responsible for looking up the
            server's IP address and connecting to it.
    """

    hostname: str
    port: int = 443

    # Set if SSLyze is directly connecting to the server ie. connection_type == DIRECT
    ip_address: Optional[str] = None

    # Set if SSLyze is connecting via a proxy ie. connection_type == VIA_HTTP_PROXY
    http_proxy_settings: Optional[HttpProxySettings] = None

    @property
    def display_string(self) -> str:
        """How to display this location to a user."""
        return f"{self.hostname}:{self.port}"

    @property
    def connection_type(self) -> ConnectionTypeEnum:
        if self.ip_address:
            return ConnectionTypeEnum.DIRECT
        elif self.http_proxy_settings:
            return ConnectionTypeEnum.VIA_HTTP_PROXY
        else:
            raise ValueError("Should never happen")

    def __post_init__(self) -> None:
        # Official workaround for frozen=True: https://docs.python.org/3/library/dataclasses.html#frozen-instances
        # Store the hostname in ACE format in the case the domain name is unicode
        hostname = self.hostname
        object.__setattr__(self, "hostname", hostname.encode("idna").decode("utf-8"))

        if self.http_proxy_settings and self.ip_address:
            raise ValueError(
                "Cannot supply both ip_address and http_proxy_settings: when using an HTTP proxy, the proxy will lookup"
                "the server's IP address automatically."
            )

        if not self.ip_address and not self.http_proxy_settings:
            # Automatically lookup the IP address
            ip_address = _do_dns_lookup(self.hostname, self.port)
            object.__setattr__(self, "ip_address", ip_address)


def _do_dns_lookup(hostname: str, port: int) -> str:
    try:
        addr_infos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.IPPROTO_IP)
    except (socket.gaierror, IndexError, ConnectionError):
        raise ServerHostnameCouldNotBeResolved(f"Could not resolve {hostname}")

    family, socktype, proto, canonname, sockaddr = addr_infos[0]

    # By default use the first DNS entry, IPv4 or IPv6
    tentative_ip_addr = sockaddr[0]

    # But try to use IPv4 if we have both IPv4 and IPv6 addresses, to work around buggy networks
    for family, socktype, proto, canonname, sockaddr in addr_infos:
        if family == socket.AF_INET:
            tentative_ip_addr = sockaddr[0]

    return tentative_ip_addr


@dataclass(frozen=True)
class ClientAuthenticationCredentials:
    """Everything needed by a client to perform SSL/TLS client authentication with the server.

    Attributes:
        certificate_chain_path: Path to the file containing the client's certificate.
        key_path: Path to the file containing the client's private key.
        key_password: The password to decrypt the private key.
        key_type: The format of the key file.
    """

    certificate_chain_path: Path
    key_path: Path
    key_password: str = ""
    key_type: OpenSslFileTypeEnum = OpenSslFileTypeEnum.PEM

    def __post_init__(self) -> None:
        # Try to load the cert and key in OpenSSL; will raise an exception if something is wrong
        SslClient(
            client_certificate_chain=self.certificate_chain_path,
            client_key=self.key_path,
            client_key_type=self.key_type,
            client_key_password=self.key_password,
        )


@dataclass(frozen=True)
class ServerNetworkConfiguration:
    """Additional network settings to provide fine-grained control on how to connect to a specific server.

    Attributes:
        tls_server_name_indication: The hostname to set within the Server Name Indication TLS extension.
        tls_wrapped_protocol: The protocol wrapped in TLS that the server expects. It allows SSLyze to figure out
            how to establish a (Start)TLS connection to the server and what kind of "hello" message
            (SMTP, XMPP, etc.) to send to the server after the handshake was completed. If not supplied, standard
            TLS will be used.
        tls_client_auth_credentials: The client certificate and private key needed to perform mutual authentication
            with the server. If not supplied, SSLyze will attempt to connect to the server without performing
            client authentication.
        xmpp_to_hostname: The hostname to set within the `to` attribute of the XMPP stream. If not supplied, the
            server's hostname will be used. Should only be set if the supplied `tls_wrapped_protocol` is an
            XMPP protocol.
        network_timeout: The timeout (in seconds) to be used when attempting to establish a connection to the
            server.
        network_max_retries: The number of retries SSLyze will perform when attempting to establish a connection
            to the server.
    """

    tls_server_name_indication: str
    tls_opportunistic_encryption: Optional[ProtocolWithOpportunisticTlsEnum] = None
    tls_client_auth_credentials: Optional[ClientAuthenticationCredentials] = None

    xmpp_to_hostname: Optional[str] = None

    network_timeout: int = 5
    network_max_retries: int = 3

    def __post_init__(self) -> None:
        if self.tls_opportunistic_encryption in [
            ProtocolWithOpportunisticTlsEnum.XMPP,
            ProtocolWithOpportunisticTlsEnum.XMPP_SERVER,
        ]:
            if not self.xmpp_to_hostname:
                # Official workaround for frozen: https://docs.python.org/3/library/dataclasses.html#frozen-instances
                # If no XMPP to hostname was supplied, used the ones from SNI
                object.__setattr__(self, "xmpp_to_hostname", self.tls_server_name_indication)
        else:
            if self.xmpp_to_hostname:
                raise InvalidServerNetworkConfigurationError("Can only specify xmpp_to for the XMPP StartTLS protocol.")

    @classmethod
    def default_for_server_location(cls, server_location: ServerNetworkLocation) -> "ServerNetworkConfiguration":
        return cls(tls_server_name_indication=server_location.hostname)
