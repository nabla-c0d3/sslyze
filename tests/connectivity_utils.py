from typing import Optional

from sslyze import ServerNetworkLocation, ServerNetworkConfiguration
from sslyze.server_connectivity import ServerConnectivityInfo, check_connectivity_to_server


def check_connectivity_to_server_and_return_info(
    server_location: ServerNetworkLocation,
    network_configuration: Optional[ServerNetworkConfiguration] = None,
) -> ServerConnectivityInfo:
    if network_configuration is None:
        final_network_config = ServerNetworkConfiguration.default_for_server_location(server_location)
    else:
        final_network_config = network_configuration

    tls_probing_result = check_connectivity_to_server(server_location, final_network_config)

    return ServerConnectivityInfo(
        server_location=server_location,
        network_configuration=final_network_config,
        tls_probing_result=tls_probing_result,
    )
