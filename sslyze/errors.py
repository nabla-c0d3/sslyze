from abc import ABC
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation


class InvalidServerNetworkConfigurationError(Exception):
    """Raised when trying to create a ServerNetworkConfiguration with invalid settings."""


class ServerHostnameCouldNotBeResolved(Exception):
    """Raised when trying to create a ServerNetworkLocationViaDirectConnection but DNS lookup failed."""


@dataclass
class ConnectionToServerFailed(Exception):
    """Parent class for all exceptions raised when a connecting to a server failed."""

    server_location: "ServerNetworkLocation"
    network_configuration: "ServerNetworkConfiguration"
    error_message: str

    def __str__(self) -> str:
        return f'{self.server_location.display_string} -> "{self.error_message}".'


@dataclass
class ConnectionToServerTimedOut(ConnectionToServerFailed):
    pass


@dataclass
class ServerRejectedConnection(ConnectionToServerFailed):
    pass


@dataclass
class ConnectionToHttpProxyFailed(ConnectionToServerFailed):
    pass


@dataclass
class ConnectionToHttpProxyTimedOut(ConnectionToHttpProxyFailed):
    pass


@dataclass
class HttpProxyRejectedConnection(ConnectionToHttpProxyFailed):
    pass


@dataclass
class ServerRejectedOpportunisticTlsNegotiation(ConnectionToServerFailed):
    pass


@dataclass
class TlsHandshakeFailed(ABC, ConnectionToServerFailed):
    pass


@dataclass
class ServerRejectedTlsHandshake(TlsHandshakeFailed):
    pass


@dataclass
class ServerTlsConfigurationNotSupported(TlsHandshakeFailed):
    pass


@dataclass
class TlsHandshakeTimedOut(TlsHandshakeFailed):
    """Raised when the initial socket connection to the server succeeded, but the TLS handshake then timed out.

    This means that the server is definitely reachable/online, but its TLS stack is buggy or it does not support the TLS
    versions SSLyze enabled in the handshake.

    See https://github.com/nabla-c0d3/sslyze/issues/445 for more details.
    """
