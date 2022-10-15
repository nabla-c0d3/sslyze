import socket
from enum import Enum, unique
from pathlib import Path
from typing import Optional

from dataclasses import dataclass

from nassl import _nassl
from nassl.ssl_client import ClientCertificateRequested, SslClient

from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration
from sslyze.errors import (
    ServerRejectedTlsHandshake,
    ServerTlsConfigurationNotSupported,
    TlsHandshakeFailed,
    ConnectionToServerFailed,
)
from sslyze.connection_helpers.tls_connection import SslConnection, _HANDSHAKE_REJECTED_TLS_ERRORS


@unique
class ClientAuthRequirementEnum(str, Enum):
    """Whether the server asked for client authentication."""

    DISABLED = "DISABLED"
    OPTIONAL = "OPTIONAL"
    REQUIRED = "REQUIRED"


@unique
class TlsVersionEnum(Enum):
    # WARNING: It has to be ordered and to match the values of nassl's OpenSslVersionEnum
    SSL_2_0 = 1
    SSL_3_0 = 2
    TLS_1_0 = 3
    TLS_1_1 = 4
    TLS_1_2 = 5
    TLS_1_3 = 6


@dataclass(frozen=True)
class ServerTlsProbingResult:
    """Additional details about the server, detected via connectivity testing."""

    highest_tls_version_supported: TlsVersionEnum
    cipher_suite_supported: str  # The OpenSSL name/string of cipher suite(s) supported by the server
    client_auth_requirement: ClientAuthRequirementEnum
    supports_ecdh_key_exchange: bool


def check_connectivity_to_server(
    server_location: ServerNetworkLocation, network_configuration: ServerNetworkConfiguration
) -> ServerTlsProbingResult:
    """Attempt to perform a full SSL/TLS handshake with the server.

    This method will ensure that the server can be reached, and will also identify one SSL/TLS version and one
    cipher suite that is supported by the server.

    Args:
        server_location
        network_configuration

    Returns:
        ServerTlsProbingResult

    Raises:
        ServerConnectivityError: If the server was not reachable or an SSL/TLS handshake could not be completed.
    """
    # Try to complete an SSL handshake to figure out the SSL/TLS version and cipher supported by the server
    tls_detection_result: Optional[_TlsVersionDetectionResult] = None

    # Fist try TLS 1.3
    try:
        tls_detection_result = _detect_support_for_tls_1_3(
            server_location=server_location,
            network_config=network_configuration,
        )
    except _TlsVersionNotSupported:
        pass

    # If TLS 1.3 is not supported, try lower versions of SSL/TLS
    if tls_detection_result is None:
        for tls_version in [
            # Order is important here as we want to detect the highest version of TLS that's supported
            TlsVersionEnum.TLS_1_2,
            TlsVersionEnum.TLS_1_1,
            TlsVersionEnum.TLS_1_0,
            TlsVersionEnum.SSL_3_0,
        ]:
            try:
                tls_detection_result = _detect_support_for_tls_1_2_or_below(
                    server_location=server_location,
                    network_config=network_configuration,
                    tls_version=tls_version,
                )
                break
            except _TlsVersionNotSupported:
                # Try the next TLS version
                pass

    if tls_detection_result is None:
        raise ServerTlsConfigurationNotSupported(
            server_location=server_location,
            network_configuration=network_configuration,
            error_message="TLS probing failed: could not find a TLS version and cipher suite supported by the server",
        )

    # If the server requested a client certificate, detect if the client cert is optional or required
    client_auth_requirement = ClientAuthRequirementEnum.DISABLED
    if tls_detection_result.server_requested_client_cert:
        if tls_detection_result.tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
            client_auth_requirement = _detect_client_auth_requirement_with_tls_1_3(
                server_location=server_location,
                network_config=network_configuration,
            )
        else:
            client_auth_requirement = _detect_client_auth_requirement_with_tls_1_2_or_below(
                server_location=server_location,
                network_config=network_configuration,
                tls_version=tls_detection_result.tls_version_supported,
                cipher_list=tls_detection_result.cipher_suite_supported,
            )

    # Check if ECDH key exchanges are supported, for the elliptic curves plugin
    if "ECDH" in tls_detection_result.cipher_suite_supported:
        is_ecdh_key_exchange_supported = True
    else:
        is_ecdh_key_exchange_supported = _detect_ecdh_support(
            server_location=server_location,
            network_config=network_configuration,
            tls_version=tls_detection_result.tls_version_supported,
        )

    # All done with TLS probing
    return ServerTlsProbingResult(
        highest_tls_version_supported=tls_detection_result.tls_version_supported,
        cipher_suite_supported=tls_detection_result.cipher_suite_supported,
        client_auth_requirement=client_auth_requirement,
        supports_ecdh_key_exchange=is_ecdh_key_exchange_supported,
    )


@dataclass(frozen=True)
class ServerConnectivityInfo:
    """All the settings (hostname, port, SSL version, etc.) needed to successfully connect to a given SSL/TLS server.

    Attributes:
        server_location: The minimum information needed to establish a connection to the server.
        network_configuration: Some additional configuration regarding how to connect to the server.
        tls_probing_result: Some additional details about the server's TLS configuration.
    """

    server_location: ServerNetworkLocation
    network_configuration: ServerNetworkConfiguration
    tls_probing_result: ServerTlsProbingResult

    def get_preconfigured_tls_connection(
        self,
        override_tls_version: Optional[TlsVersionEnum] = None,
        ca_certificates_path: Optional[Path] = None,
        should_use_legacy_openssl: Optional[bool] = None,
        should_enable_server_name_indication: bool = True,
    ) -> SslConnection:
        """Get an SSLConnection instance with the right SSL configuration for successfully connecting to the server.

        Used by all plugins to connect to the server and run scans.
        """
        final_ssl_version = self.tls_probing_result.highest_tls_version_supported
        final_openssl_cipher_string: Optional[str]
        final_openssl_cipher_string = self.tls_probing_result.cipher_suite_supported
        if override_tls_version is not None:
            # Caller wants to override the TLS version to use for this connection
            final_ssl_version = override_tls_version
            # Then we don't know which cipher suite is supported by the server for this ssl version
            final_openssl_cipher_string = None

        if should_use_legacy_openssl is not None:
            final_openssl_cipher_string = None

        if self.network_configuration.tls_client_auth_credentials is not None:
            # If we have creds for client authentication, go ahead and use them
            should_ignore_client_auth = False
        else:
            # Ignore client auth requests if the server allows optional TLS client authentication
            should_ignore_client_auth = True
            # But do not ignore them is client authentication is required so that the right exceptions get thrown
            # within the plugins, providing a better output
            if self.tls_probing_result.client_auth_requirement == ClientAuthRequirementEnum.REQUIRED:
                should_ignore_client_auth = False

        ssl_connection = SslConnection(
            server_location=self.server_location,
            network_configuration=self.network_configuration,
            tls_version=final_ssl_version,
            should_ignore_client_auth=should_ignore_client_auth,
            ca_certificates_path=ca_certificates_path,
            should_use_legacy_openssl=should_use_legacy_openssl,
            should_enable_server_name_indication=should_enable_server_name_indication,
        )
        if final_openssl_cipher_string:
            if final_ssl_version == TlsVersionEnum.TLS_1_3:
                # OpenSSL uses a different API for TLS 1.3
                if not isinstance(ssl_connection.ssl_client, SslClient):
                    raise RuntimeError("Should never happen")
                ssl_connection.ssl_client.set_ciphersuites(final_openssl_cipher_string)
            else:
                ssl_connection.ssl_client.set_cipher_list(final_openssl_cipher_string)

        return ssl_connection


@dataclass(frozen=True)
class _TlsVersionDetectionResult:
    tls_version_supported: TlsVersionEnum
    cipher_suite_supported: str
    server_requested_client_cert: bool


class _TlsVersionNotSupported(Exception):
    pass


def _detect_support_for_tls_1_3(
    server_location: ServerNetworkLocation,
    network_config: ServerNetworkConfiguration,
) -> _TlsVersionDetectionResult:
    ssl_connection = SslConnection(
        server_location=server_location,
        network_configuration=network_config,
        tls_version=TlsVersionEnum.TLS_1_3,
        should_ignore_client_auth=False,
    )

    try:
        ssl_connection.connect(should_retry_connection=False)
        return _TlsVersionDetectionResult(
            tls_version_supported=TlsVersionEnum.TLS_1_3,
            server_requested_client_cert=False,
            cipher_suite_supported=ssl_connection.ssl_client.get_current_cipher_name(),
        )
    except ClientCertificateRequested:
        # Connection successful but the servers wants a client certificate which wasn't supplied to sslyze
        return _TlsVersionDetectionResult(
            tls_version_supported=TlsVersionEnum.TLS_1_3,
            server_requested_client_cert=True,
            cipher_suite_supported=ssl_connection.ssl_client.get_current_cipher_name(),
        )

    except TlsHandshakeFailed:
        pass

    except (OSError, _nassl.OpenSSLError) as e:
        # If these errors get propagated here, it means they're not part of the known/normal errors that
        # can happen when trying to connect to a server and defined in tls_connection.py
        # Hence we re-raise these as "unknown" connection errors; might be caused by bad connectivity to
        # the server (random disconnects, etc.) and the scan against this server should not be performed
        raise ConnectionToServerFailed(
            server_location=server_location,
            network_configuration=network_config,
            error_message=f'Unexpected connection error: "{e.args}"',
        )

    finally:
        ssl_connection.close()

    # If we get here, none of the handshakes were successful
    raise _TlsVersionNotSupported()


def _detect_support_for_tls_1_2_or_below(
    server_location: ServerNetworkLocation,
    network_config: ServerNetworkConfiguration,
    tls_version: TlsVersionEnum,
) -> _TlsVersionDetectionResult:
    # First try the default cipher list, and then all ciphers; this is to work around F5 network devices
    # that time out when the client hello is too long (ie. too many cipher suites enabled)
    # https://support.f5.com/csp/article/K14758
    for cipher_list in ["DEFAULT", "ALL:COMPLEMENTOFALL:-PSK:-SRP"]:
        ssl_connection = SslConnection(
            server_location=server_location,
            network_configuration=network_config,
            tls_version=tls_version,
            should_ignore_client_auth=False,
        )
        ssl_connection.ssl_client.set_cipher_list(cipher_list)

        try:
            # Only do one attempt when testing connectivity
            ssl_connection.connect(should_retry_connection=False)
            return _TlsVersionDetectionResult(
                tls_version_supported=tls_version,
                server_requested_client_cert=False,
                cipher_suite_supported=ssl_connection.ssl_client.get_current_cipher_name(),
            )

        except ClientCertificateRequested:
            # Connection successful but the servers wants a client certificate which wasn't supplied to sslyze
            return _TlsVersionDetectionResult(
                tls_version_supported=tls_version,
                server_requested_client_cert=True,
                # Calling ssl_connection.ssl_client.get_current_cipher_name() will fail in this situation so we just
                # store the whole cipher_list
                cipher_suite_supported=cipher_list,
            )

        except TlsHandshakeFailed:
            # Try the next cipher list
            pass

        except (OSError, _nassl.OpenSSLError) as e:
            # If these errors get propagated here, it means they're not part of the known/normal errors that
            # can happen when trying to connect to a server and defined in tls_connection.py
            # Hence we re-raise these as "unknown" connection errors; might be caused by bad connectivity to
            # the server (random disconnects, etc.) and the scan against this server should not be performed
            raise ConnectionToServerFailed(
                server_location=server_location,
                network_configuration=network_config,
                error_message=f'Unexpected connection error: "{e.args}"',
            )

        finally:
            ssl_connection.close()

    # If we get here, none of the handshakes were successful
    raise _TlsVersionNotSupported()


def _detect_client_auth_requirement_with_tls_1_3(
    server_location: ServerNetworkLocation,
    network_config: ServerNetworkConfiguration,
) -> ClientAuthRequirementEnum:
    """Try to detect if client authentication is optional or required."""
    ssl_connection_auth = SslConnection(
        server_location=server_location,
        network_configuration=network_config,
        tls_version=TlsVersionEnum.TLS_1_3,
        should_ignore_client_auth=True,
    )
    try:
        ssl_connection_auth.connect(should_retry_connection=False)

        # With TLS 1.3 we need to send some data and then read the response
        # to force a ClientCertificateRequested exception; not sure why
        # https://github.com/nabla-c0d3/sslyze/issues/472
        ssl_connection_auth.ssl_client.write(b"A")
        ssl_connection_auth.ssl_client.read(1)

        client_auth_requirement = ClientAuthRequirementEnum.OPTIONAL

    except (ClientCertificateRequested, ServerRejectedTlsHandshake):
        client_auth_requirement = ClientAuthRequirementEnum.REQUIRED

    except socket.timeout:
        # The timeout is triggered when calling read() because the server has client auth optional and is waiting for
        # more data from us the client
        client_auth_requirement = ClientAuthRequirementEnum.OPTIONAL

    except _nassl.OpenSSLError as e:
        # Here we re-use some of the rejection handling logic already implemented in SslConnection.connect()
        # This is because the call to read(1) in the try block might trigger similar errors as connect()
        # https://github.com/nabla-c0d3/sslyze/issues/562
        # TODO(AD): Find a way to unify exception handling between the two calls
        openssl_error_message = e.args[0]
        is_known_server_rejection_error = False
        for error_msg in _HANDSHAKE_REJECTED_TLS_ERRORS.keys():
            if error_msg in openssl_error_message:
                is_known_server_rejection_error = True
                break

        if is_known_server_rejection_error:
            client_auth_requirement = ClientAuthRequirementEnum.REQUIRED
        else:
            raise

    finally:
        ssl_connection_auth.close()

    return client_auth_requirement


def _detect_client_auth_requirement_with_tls_1_2_or_below(
    server_location: ServerNetworkLocation,
    network_config: ServerNetworkConfiguration,
    tls_version: TlsVersionEnum,
    cipher_list: str,
) -> ClientAuthRequirementEnum:
    """Try to detect if client authentication is optional or required."""
    if tls_version.value >= TlsVersionEnum.TLS_1_3.value:
        raise ValueError("Use _detect_client_auth_requirement_with_tls_1_3()")

    ssl_connection_auth = SslConnection(
        server_location=server_location,
        network_configuration=network_config,
        tls_version=tls_version,
        should_ignore_client_auth=True,
    )
    ssl_connection_auth.ssl_client.set_cipher_list(cipher_list)

    try:
        ssl_connection_auth.connect(should_retry_connection=False)
        client_auth_requirement = ClientAuthRequirementEnum.OPTIONAL
    except (ClientCertificateRequested, ServerRejectedTlsHandshake):
        client_auth_requirement = ClientAuthRequirementEnum.REQUIRED
    finally:
        ssl_connection_auth.close()

    return client_auth_requirement


def _detect_ecdh_support(
    server_location: ServerNetworkLocation,
    network_config: ServerNetworkConfiguration,
    tls_version: TlsVersionEnum,
) -> bool:
    if tls_version.value < TlsVersionEnum.TLS_1_2.value:
        # Retrieving ECDH information is only implemented in the modern nassl.SslClient, which is TLS 1.2+
        return False

    is_ecdh_key_exchange_supported = False
    ssl_connection = SslConnection(
        server_location=server_location,
        network_configuration=network_config,
        tls_version=tls_version,
        should_use_legacy_openssl=False,
        should_ignore_client_auth=True,
    )
    if not isinstance(ssl_connection.ssl_client, SslClient):
        raise RuntimeError(
            "Should never happen: specified should_use_legacy_openssl=False but didn't get the modern" " SSL client"
        )

    # Set the right elliptic curve cipher suites
    enable_ecdh_cipher_suites(tls_version, ssl_connection.ssl_client)
    try:
        ssl_connection.connect(should_retry_connection=False)
        is_ecdh_key_exchange_supported = True
    except ClientCertificateRequested:
        is_ecdh_key_exchange_supported = True
    except ServerRejectedTlsHandshake:
        is_ecdh_key_exchange_supported = False
    finally:
        ssl_connection.close()

    return is_ecdh_key_exchange_supported


def enable_ecdh_cipher_suites(tls_version: TlsVersionEnum, ssl_client: SslClient) -> None:
    """Set the elliptic curve cipher suites."""
    if tls_version == TlsVersionEnum.TLS_1_3:
        # Cipher suites source: https://tools.ietf.org/html/rfc8446#appendix-B.4
        ssl_client.set_ciphersuites(
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"
        )
    else:
        # TLSv1.2; cipher suite source: https://www.openssl.org/docs/man1.0.2/man1/ciphers.html
        ssl_client.set_cipher_list("ECDH")
