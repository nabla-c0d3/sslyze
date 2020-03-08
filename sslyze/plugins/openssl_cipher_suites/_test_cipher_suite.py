from dataclasses import dataclass
from typing import Optional, Union

from nassl.ssl_client import OpenSslVersionEnum, ClientCertificateRequested

from sslyze.connection_helpers.errors import (
    ServerRejectedTlsHandshake,
    ServerTlsConfigurationNotSupported,
    ConnectionToServerFailed,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite, CipherSuitesRepository
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.plugins.openssl_cipher_suites._tls12_workaround import WorkaroundForTls12ForCipherSuites


@dataclass(frozen=True)
class CipherSuiteAcceptedByServer:
    cipher_suite: CipherSuite
    # TODO: dh_info


@dataclass(frozen=True)
class CipherSuiteRejectedByServer:
    cipher_suite: CipherSuite
    error_message: str


def connect_with_cipher_suite(
    server_connectivity_info: ServerConnectivityInfo, tls_version: OpenSslVersionEnum, cipher_suite: CipherSuite
) -> Union[CipherSuiteAcceptedByServer, CipherSuiteRejectedByServer]:
    """Initiates a SSL handshake with the server using the SSL version and the cipher suite specified.
    """
    requires_legacy_openssl = True
    if tls_version == OpenSslVersionEnum.TLSV1_2:
        # For TLS 1.2, we need to pick the right version of OpenSSL depending on which cipher suite
        requires_legacy_openssl = WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(cipher_suite.openssl_name)
    elif tls_version == OpenSslVersionEnum.TLSV1_3:
        requires_legacy_openssl = False

    ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, should_use_legacy_openssl=requires_legacy_openssl
    )

    # Only enable the cipher suite to test; not trivial anymore since OpenSSL 1.1.1 and TLS 1.3
    if tls_version == OpenSslVersionEnum.TLSV1_3:
        # The function to control cipher suites is different for TLS 1.3
        # Disable the default, non-TLS 1.3 cipher suites
        ssl_connection.ssl_client.set_cipher_list("")
        # Enable the one TLS 1.3 cipher suite we want to test
        ssl_connection.ssl_client.set_ciphersuites(cipher_suite.openssl_name)
    else:
        if not requires_legacy_openssl:
            # Disable the TLS 1.3 cipher suites if we are using the modern client
            ssl_connection.ssl_client.set_ciphersuites("")

        ssl_connection.ssl_client.set_cipher_list(cipher_suite.openssl_name)

    if len(ssl_connection.ssl_client.get_cipher_list()) != 1:
        raise ValueError(
            f'Passed an OpenSSL string for multiple cipher suites: "{cipher_suite.openssl_name}": '
            f"{str(ssl_connection.ssl_client.get_cipher_list())}"
        )

    try:
        # Perform the SSL handshake
        ssl_connection.connect()

    except ServerTlsConfigurationNotSupported:
        # SSLyze rejected the handshake because the server's DH config was too insecure; this means the
        # cipher suite is actually supported
        return CipherSuiteAcceptedByServer(cipher_suite=cipher_suite)

    except ClientCertificateRequested:
        # When the handshake failed due to ClientCertificateRequested
        return CipherSuiteAcceptedByServer(cipher_suite=cipher_suite)

    except ServerRejectedTlsHandshake as e:
        return CipherSuiteRejectedByServer(cipher_suite=cipher_suite, error_message=e.error_message)
    finally:
        ssl_connection.close()

    return CipherSuiteAcceptedByServer(cipher_suite=cipher_suite)


@dataclass(frozen=True)
class PreferredCipherSuite:
    cipher_suite: Optional[CipherSuite]


def get_preferred_cipher_suite(
    server_connectivity_info: ServerConnectivityInfo, tls_version: OpenSslVersionEnum
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
        return PreferredCipherSuite(
            CipherSuite.from_openssl(cipher_suite_openssl_name=cipher_suite_used_with_order, tls_version=tls_version)
        )
    else:
        # The server has no preferred cipher suite as it follows the client's preference for picking a cipher suite
        return PreferredCipherSuite(None)


def _get_selected_cipher_suite(
    server_connectivity: ServerConnectivityInfo, tls_version: OpenSslVersionEnum, openssl_cipher_string: str
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
