import socket
from abc import ABC
from typing import Optional

from dataclasses import dataclass
from urllib.parse import urlparse


from sslyze.ssl_settings import (
    TlsWrappedProtocolEnum,
    ClientAuthenticationCredentials,
)



@dataclass(frozen=True)
class HttpProxySettings:
    hostname: str
    port: int

    basic_auth_user: Optional[str]
    basic_auth_password: Optional[str]

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


@dataclass(frozen=True)
class ServerNetworkLocation(ABC):
    hostname: str
    port: int

    def __init__(self, hostname: str, port: int) -> None:
        # Official workaround for frozen=True: https://docs.python.org/3/library/dataclasses.html#frozen-instances
        # Store the hostname in ACE format in the case the domain name is unicode
        object.__setattr__(self, "hostname", hostname.encode("idna").decode("utf-8"))
        object.__setattr__(self, "port", port)


# TODO
class ServerHostnameCouldNotBeResolved(Exception):
    pass


@dataclass(frozen=True)
class ServerNetworkLocationThroughDirectConnection(ServerNetworkLocation):
    """
    Attributes:
        hostname: The server's hostname.
        port: The server's TLS port number.
        ip_address: The server's IP address. If you do not have the server's IP address, instantiate this class using
            `with_ip_address_lookup()` to do a DNS lookup for the specified `hostname`.
    """

    ip_address: str

    @staticmethod
    def _do_dns_lookup(hostname: str, port: int) -> str:
        addr_infos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.IPPROTO_IP)
        family, socktype, proto, canonname, sockaddr = addr_infos[0]

        # By default use the first DNS entry, IPv4 or IPv6
        tentative_ip_addr = sockaddr[0]

        # But try to use IPv4 if we have both IPv4 and IPv6 addresses, to work around buggy networks
        for family, socktype, proto, canonname, sockaddr in addr_infos:
            if family == socket.AF_INET:
                tentative_ip_addr = sockaddr[0]

        return tentative_ip_addr

    @classmethod
    def with_ip_address_lookup(cls, hostname, port):
        try:
            # Do a DNS lookup if we don't already have an IP address
            ip_address = cls._do_dns_lookup(hostname, port)
        except (socket.gaierror, IndexError, ConnectionError):
            raise ServerHostnameCouldNotBeResolved()

        return cls(hostname=hostname, port=port, ip_address=ip_address)


@dataclass(frozen=True)
class ServerNetworkLocationThroughProxy(ServerNetworkLocation):
    """
    Attributes:
        hostname: The server's hostname.
        port: The server's TLS port number.
        http_proxy_settings: The HTTP proxy configuration to use in order to tunnel the scans through a proxy. The
            proxy will ber esponsible for looking up the server's IP address and connecting to it.
    """
    http_proxy_settings: HttpProxySettings


@dataclass(frozen=True)
class ServerTlsConfiguration:
    """
    Attributes:
        tls_wrapped_protocol: The protocol wrapped in TLS that the server expects. It allows sslyze to figure out
            how to establish a (Start)TLS connection to the server and what kind of "hello" message
            (SMTP, XMPP, etc.) to send to the server after the handshake was completed. If not supplied, standard
            TLS will be used.
        tls_server_name_indication: The hostname to set within the Server Name Indication TLS extension. If not
            supplied, the server's hostname will be used.
        xmpp_to_hostname: The hostname to set within the `to` attribute of the XMPP stream. If not supplied, the
            server's hostname will be used. Should only be set if the supplied `tls_wrapped_protocol` is an
            XMPP protocol.
        client_auth_credentials: The client certificate and private key needed to perform mutual authentication
            with the server. If not supplied, sslyze will attempt to connect to the server without performing
            mutual authentication.
    """
    # Additional settings
    tls_wrapped_protocol: TlsWrappedProtocolEnum
    tls_server_name_indication: str
    xmpp_to_hostname: Optional[str]
    client_auth_credentials: Optional[ClientAuthenticationCredentials]

    def __post_init__(self):
        if self.xmpp_to_hostname and self.tls_wrapped_protocol not in [
            TlsWrappedProtocolEnum.STARTTLS_XMPP,
            TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER,
        ]:
            raise ValueError("Can only specify xmpp_to for the XMPP StartTLS protocol.")

    @classmethod
    def get_default(cls, server_hostname: str):
        return cls(
            tls_wrapped_protocol=TlsWrappedProtocolEnum.PLAIN_TLS,
            tls_server_name_indication=server_hostname,
            xmpp_to_hostname=None,
            client_auth_credentials=None,
        )
