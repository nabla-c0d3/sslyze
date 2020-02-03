from dataclasses import dataclass
from typing import Optional, Union

from nassl.ssl_client import OpenSslVersionEnum, ClientCertificateRequested

from sslyze.connection_helpers.errors import ServerRejectedTlsHandshake, ServerTlsConfigurationNotSupported, \
    ConnectionToServerFailed
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.plugins.openssl_cipher_suites.tls12_workaround import WorkaroundForTls12ForCipherSuites


@dataclass(frozen=True)
class CipherSuiteAcceptedByServer:
    cipher_suite: CipherSuite
    # TODO: dh_info


@dataclass(frozen=True)
class CipherSuiteRejectedByServer:
    cipher_suite: CipherSuite
    error_message: str


def test_cipher_suite(
    server_connectivity_info: ServerConnectivityInfo,
    tls_version: OpenSslVersionEnum,
    cipher_openssl_name: str,
) -> Union[CipherSuiteAcceptedByServer, CipherSuiteRejectedByServer]:
    """Initiates a SSL handshake with the server using the SSL version and the cipher suite specified.
    """
    requires_legacy_openssl = True
    if tls_version == OpenSslVersionEnum.TLSV1_2:
        # For TLS 1.2, we need to pick the right version of OpenSSL depending on which cipher suite
        requires_legacy_openssl = WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(cipher_openssl_name)
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
        ssl_connection.ssl_client.set_ciphersuites(cipher_openssl_name)
    else:
        if not requires_legacy_openssl:
            # Disable the TLS 1.3 cipher suites if we are using the modern client
            ssl_connection.ssl_client.set_ciphersuites("")

        ssl_connection.ssl_client.set_cipher_list(cipher_openssl_name)

    if len(ssl_connection.ssl_client.get_cipher_list()) != 1:
        raise ValueError(
            f'Passed an OpenSSL string for multiple cipher suites: "{cipher_openssl_name}": '
            f"{str(ssl_connection.ssl_client.get_cipher_list())}"
        )

    cipher_suite = CipherSuite.from_openssl(cipher_suite_openssl_name=cipher_openssl_name, tls_version=tls_version)
    try:
        # Perform the SSL handshake
        ssl_connection.connect()

    except ServerTlsConfigurationNotSupported:
        # SSLyze rejected the handshake because the server's DH config was too insecure; this means the
        # cipher suite is actually supported
        return CipherSuiteAcceptedByServer(
            cipher_suite=cipher_suite,
        )

    except ClientCertificateRequested:
        # When the handshake failed due to ClientCertificateRequested
        return CipherSuiteAcceptedByServer(
            cipher_suite=cipher_suite,
        )

    except ServerRejectedTlsHandshake as e:
        return CipherSuiteRejectedByServer(
            cipher_suite=cipher_suite,
            error_message=e.error_message
        )
    finally:
        ssl_connection.close()

    return CipherSuiteAcceptedByServer(
        cipher_suite=cipher_suite,
    )


def get_preferred_cipher_suite(
    cls,
    server_connectivity_info: ServerConnectivityInfo,
    tls_version: OpenSslVersionEnum,
    cipher_suites_to_enable: str,
) -> Optional[CipherSuite]:
    """Try to detect the server's preferred cipher suite among all cipher suites supported by SSLyze.
    """
    should_use_legacy_openssl = None
    # For TLS 1.2, we need to figure whether the modern or legacy OpenSSL should be used to connect
    if tls_version == OpenSslVersionEnum.TLSV1_2:
        should_use_legacy_openssl = True
        # If there are more than two modern-supported cipher suites, use the modern OpenSSL
        for cipher_name in accepted_cipher_names:
            modern_supported_cipher_count = 0
            if not WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(cipher_name):
                modern_supported_cipher_count += 1

            if modern_supported_cipher_count > 1:
                should_use_legacy_openssl = False
                break

    first_cipher_str = ", ".join(accepted_cipher_names)
    # Swap the first two ciphers in the list to see if the server always picks the client's first cipher
    second_cipher_str = ", ".join([accepted_cipher_names[1], accepted_cipher_names[0]] + accepted_cipher_names[2:])

    try:
        first_cipher = cls._get_selected_cipher_suite(
            server_connectivity_info, tls_version, first_cipher_str, should_use_legacy_openssl
        )
        second_cipher = cls._get_selected_cipher_suite(
            server_connectivity_info, tls_version, second_cipher_str, should_use_legacy_openssl
        )
    except (ConnectionToServerFailed):
        # Could not complete a handshake
        return None

    if first_cipher.name == second_cipher.name:
        # The server has its own preference for picking a cipher suite
        return first_cipher
    else:
        # The server has no preferred cipher suite as it follows the client's preference for picking a cipher suite
        return None


def _get_selected_cipher_suite(
    server_connectivity: ServerConnectivityInfo,
    ssl_version: OpenSslVersionEnum,
    openssl_cipher_str: str,
    should_use_legacy_openssl: Optional[bool],
) -> "AcceptedCipherSuite":
    """Given an OpenSSL cipher string (which may specify multiple cipher suites), return the cipher suite that was
    selected by the server during the SSL handshake.
    """
    ssl_connection = server_connectivity.get_preconfigured_tls_connection(
        override_tls_version=ssl_version, should_use_legacy_openssl=should_use_legacy_openssl
    )
    ssl_connection.ssl_client.set_cipher_list(openssl_cipher_str)

    # Perform the SSL handshake
    try:
        ssl_connection.connect()
        selected_cipher = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
    except ClientCertificateRequested:
        selected_cipher = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
    finally:
        ssl_connection.close()
    return selected_cipher
