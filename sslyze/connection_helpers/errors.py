from abc import ABC
from dataclasses import dataclass

from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration


@dataclass(frozen=True)
class ConnectionToServerFailed(Exception):
    server_location: ServerNetworkLocation
    network_configuration: ServerNetworkConfiguration
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
