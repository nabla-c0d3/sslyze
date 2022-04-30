from abc import ABC
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration


class InvalidServerNetworkConfigurationError(Exception):
    """Raised when trying to create a ServerNetworkConfiguration with invalid settings."""


class ServerHostnameCouldNotBeResolved(Exception):
    """Raised when trying to create a ServerNetworkLocationViaDirectConnection but DNS lookup failed."""


@dataclass(frozen=True)
class ConnectionToServerFailed(Exception):
    """Parent class for all exceptions raised when a connecting to a server failed."""

    server_location: "ServerNetworkLocation"
    network_configuration: "ServerNetworkConfiguration"
    error_message: str

    def __str__(self) -> str:
        return f'{self.server_location.display_string} -> "{self.error_message}".'


@dataclass(frozen=True)
class ConnectionToServerTimedOut(ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class ServerRejectedConnection(ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class ConnectionToHttpProxyFailed(ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class ConnectionToHttpProxyTimedOut(ConnectionToHttpProxyFailed):
    pass


@dataclass(frozen=True)
class HttpProxyRejectedConnection(ConnectionToHttpProxyFailed):
    pass


@dataclass(frozen=True)
class ServerRejectedOpportunisticTlsNegotiation(ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class TlsHandshakeFailed(ABC, ConnectionToServerFailed):
    pass


@dataclass(frozen=True)
class ServerRejectedTlsHandshake(TlsHandshakeFailed):
    pass


@dataclass(frozen=True)
class ServerTlsConfigurationNotSupported(TlsHandshakeFailed):
    pass


@dataclass(frozen=True)
class TlsHandshakeTimedOut(TlsHandshakeFailed):
    """Raised when the initial socket connection to the server succeeded, but the TLS handshake then timed out.

    This means that the server is definitely reachable/online, but its TLS stack is buggy or it does not support the TLS
    versions SSLyze enabled in the handshake.

    See https://github.com/nabla-c0d3/sslyze/issues/445 for more details.
    """

    pass
