from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from nassl.ssl_client import OpenSslVersionEnum

from sslyze.server_setting import ServerNetworkLocation, ServerTlsConfiguration
from sslyze.ssl_settings import (
    ClientAuthenticationServerConfigurationEnum,
)

from sslyze.utils.ssl_connection import SslConnection

from sslyze.utils.ssl_connection_configurator import SslConnectionConfigurator


@dataclass(frozen=True)
class ServerTlsProbingResult:
    # Additional details about the server detected via connectivity testing
    highest_ssl_version_supported: OpenSslVersionEnum
    openssl_cipher_string_supported: str
    client_auth_requirement: ClientAuthenticationServerConfigurationEnum


# TODO: Update doc
@dataclass(frozen=True)
class ServerConnectivityInfo:
    """All the settings (hostname, port, SSL version, etc.) needed to successfully connect to a given SSL/TLS server.

    Such objects are returned by `ServerConnectivityTester.perform()` if connectivity testing was successful, and should
    never be instantiated directly.

    Attributes:
        network_location:
        tls_configuration:
        tls_probing_result:
    """
    network_location: ServerNetworkLocation
    tls_configuration: ServerTlsConfiguration
    tls_probing_result: ServerTlsProbingResult

    def get_preconfigured_ssl_connection(
        self,
        override_ssl_version: Optional[OpenSslVersionEnum] = None,
        ssl_verify_locations: Optional[Path] = None,
        should_use_legacy_openssl: Optional[bool] = None,
    ) -> SslConnection:
        # Use the ssl version and cipher suite that were successful during connectivity testing
        final_ssl_version = self.tls_probing_result.highest_ssl_version_supported
        final_openssl_cipher_string = self.tls_probing_result.openssl_cipher_string_supported
        if override_ssl_version is not None:
            # Caller wants to override the ssl version to use for this connection
            final_ssl_version = override_ssl_version
            # Then we don't know which cipher suite is supported by the server for this ssl version
            final_openssl_cipher_string = None

        if should_use_legacy_openssl is not None:
            final_openssl_cipher_string = None

        if self.tls_configuration.client_auth_credentials is not None:
            # If we have creds for client authentication, go ahead and use them
            should_ignore_client_auth = False
        else:
            # Ignore client auth requests if the server allows optional TLS client authentication
            should_ignore_client_auth = True
            # But do not ignore them is client authentication is required so that the right exceptions get thrown
            # within the plugins, providing a better output
            if self.tls_probing_result.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.REQUIRED:
                should_ignore_client_auth = False

        return SslConnectionConfigurator.get_connection(
            network_location=self.network_location,
            tls_configuration=self.tls_configuration,
            ssl_version=final_ssl_version,
            openssl_cipher_string=final_openssl_cipher_string,
            should_ignore_client_auth=should_ignore_client_auth,
            ssl_verify_locations=ssl_verify_locations,
            should_use_legacy_openssl=should_use_legacy_openssl,
        )
