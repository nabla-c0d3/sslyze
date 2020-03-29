from abc import ABC
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration


class InvalidServerNetworkConfigurationError(Exception):
    """Raised when trying to create a ServerNetworkConfiguration with invalid settings.
    """


class ServerHostnameCouldNotBeResolved(Exception):
    """Raised when trying to create a ServerNetworkLocationViaDirectConnection with a hostname whose DNS lookup failed.
    """


@dataclass(frozen=True)
class ConnectionToServerFailed(Exception):
    """Parent class for all exceptions raised when a connecting to a server failed.
    """

    server_location: "ServerNetworkLocation"
    network_configuration: "ServerNetworkConfiguration"
    error_message: str


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
