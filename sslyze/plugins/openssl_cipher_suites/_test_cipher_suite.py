from dataclasses import dataclass
from typing import Optional, Union

from nassl.ephemeral_key_info import EphemeralKeyInfo
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import ClientCertificateRequested, SslClient

from sslyze.errors import (
    ServerRejectedTlsHandshake,
    ServerTlsConfigurationNotSupported,
    ConnectionToServerFailed,
    TlsHandshakeTimedOut,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite, CipherSuitesRepository
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum
from sslyze.plugins.openssl_cipher_suites._tls12_workaround import WorkaroundForTls12ForCipherSuites


@dataclass(frozen=True)
class CipherSuiteAcceptedByServer:
    """
    ephemeral_key: The ephemeral key negotiated with the server when using (EC) DH cipher suites. None if the cipher
        suite does not use ephemeral keys or if the ephemeral key could not be retrieved.
    """

    cipher_suite: CipherSuite
    ephemeral_key: Optional[EphemeralKeyInfo]


@dataclass(frozen=True)
class CipherSuiteRejectedByServer:
    cipher_suite: CipherSuite
    error_message: str


def connect_with_cipher_suite(
    server_connectivity_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, cipher_suite: CipherSuite
) -> Union[CipherSuiteAcceptedByServer, CipherSuiteRejectedByServer]:
    """Initiates a SSL handshake with the server using the SSL version and the cipher suite specified.
    """
    requires_legacy_openssl = True
    if tls_version == TlsVersionEnum.TLS_1_2:
        # For TLS 1.2, we need to pick the right version of OpenSSL depending on which cipher suite
        requires_legacy_openssl = WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(cipher_suite.openssl_name)
    elif tls_version == TlsVersionEnum.TLS_1_3:
        requires_legacy_openssl = False

    ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, should_use_legacy_openssl=requires_legacy_openssl
    )

    # Only enable the cipher suite to test; not trivial anymore since OpenSSL 1.1.1 and TLS 1.3
    if isinstance(ssl_connection.ssl_client, SslClient):
        # With the modern OpenSSL client we have to manage TLS 1.3-specific cipher functions
        if tls_version == TlsVersionEnum.TLS_1_3:
            legacy_openssl_cipher_string = ""
            tls1_3_openssl_cipher_string = cipher_suite.openssl_name
        else:
            legacy_openssl_cipher_string = cipher_suite.openssl_name
            tls1_3_openssl_cipher_string = ""

        ssl_connection.ssl_client.set_ciphersuites(tls1_3_openssl_cipher_string)  # TLS 1.3 method
        ssl_connection.ssl_client.set_cipher_list(legacy_openssl_cipher_string)  # Legacy method
    elif isinstance(ssl_connection.ssl_client, LegacySslClient):
        # With the legacy OpenSSL client, nothing special to do
        ssl_connection.ssl_client.set_cipher_list(cipher_suite.openssl_name)
    else:
        raise RuntimeError("Should never happen")

    if len(ssl_connection.ssl_client.get_cipher_list()) != 1:
        raise ValueError(
            f'Passed an OpenSSL string for multiple cipher suites: "{cipher_suite.openssl_name}": '
            f"{str(ssl_connection.ssl_client.get_cipher_list())}"
        )

    ephemeral_key = None
    try:
        # Perform the SSL handshake
        ssl_connection.connect()
        ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()

    except ServerTlsConfigurationNotSupported:
        # SSLyze rejected the handshake because the server's DH config was too insecure; this means the
        # cipher suite is actually supported
        pass

    except ClientCertificateRequested:
        # When the handshake failed due to ClientCertificateRequested
        ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()
        pass

    except ServerRejectedTlsHandshake as e:
        return CipherSuiteRejectedByServer(cipher_suite=cipher_suite, error_message=e.error_message)

    except TlsHandshakeTimedOut as e:
        # Sometimes triggered by servers that don't support (at all) a specific version of TLS
        # Amazon Cloudfront does that with TLS 1.3
        # There's no easy way to differentiate this error from a network glitch/timeout
        return CipherSuiteRejectedByServer(cipher_suite=cipher_suite, error_message=e.error_message)

    finally:
        ssl_connection.close()

    return CipherSuiteAcceptedByServer(cipher_suite=cipher_suite, ephemeral_key=ephemeral_key)


@dataclass(frozen=True)
class PreferredCipherSuite:
    cipher_suite_openssl_name: Optional[str]


def get_preferred_cipher_suite(
    server_connectivity_info: ServerConnectivityInfo, tls_version: TlsVersionEnum
) -> PreferredCipherSuite:
    """Try to detect the server's preferred cipher suite among all cipher suites supported by SSLyze.
    """
    all_cipher_suites = [
        cipher_suite.openssl_name for cipher_suite in CipherSuitesRepository.get_all_cipher_suites(tls_version)
    ]
    ordered_cipher_suites = sorted(all_cipher_suites, reverse=False)
    reverse_ordered_cipher_suites = sorted(all_cipher_suites, reverse=True)

    ordered_cipher_suites_string = ":".join(ordered_cipher_suites)
    reverse_ordered_cipher_suites_string = ":".join(reverse_ordered_cipher_suites)

    try:
        cipher_suite_used_with_order = _get_selected_cipher_suite(
            server_connectivity_info, tls_version, ordered_cipher_suites_string
        )
        cipher_suite_used_with_reverse_order = _get_selected_cipher_suite(
            server_connectivity_info, tls_version, reverse_ordered_cipher_suites_string
        )
    except ConnectionToServerFailed:
        # Could not complete a handshake
        return PreferredCipherSuite(None)

    if cipher_suite_used_with_order == cipher_suite_used_with_reverse_order:
        # The server has its own preference for picking a cipher suite
        return PreferredCipherSuite(cipher_suite_openssl_name=cipher_suite_used_with_order)
    else:
        # The server has no preferred cipher suite as it follows the client's preference for picking a cipher suite
        return PreferredCipherSuite(None)


def _get_selected_cipher_suite(
    server_connectivity: ServerConnectivityInfo, tls_version: TlsVersionEnum, openssl_cipher_string: str
) -> str:
    ssl_connection = server_connectivity.get_preconfigured_tls_connection(override_tls_version=tls_version)
    ssl_connection.ssl_client.set_cipher_list(openssl_cipher_string)

    # Perform the SSL handshake
    try:
        ssl_connection.connect()
        return ssl_connection.ssl_client.get_current_cipher_name()
    except ClientCertificateRequested:
        # TODO(AD): Sometimes get_current_cipher_name() called in from_ongoing_ssl_connection() will return None
        return ssl_connection.ssl_client.get_current_cipher_name()
    finally:
        ssl_connection.close()
