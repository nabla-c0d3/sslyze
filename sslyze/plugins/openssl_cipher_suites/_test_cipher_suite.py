from dataclasses import dataclass
from typing import Optional, Union

from nassl.errors import OpenSSLError
from nassl.ephemeral_key_info import EphemeralKeyInfo
from nassl.base_ssl_client import ClientCertificateRequested
from nassl.openssl_1_1_1.ssl_client import SslClient_OpenSSL_1_1_1
from nassl.openssl_4_0_0.ssl_client import SslClient_OpenSSL_4_0_0

from sslyze.connection_helpers.tls_connection import NoCiphersAvailableBugInSSlyze
from sslyze.errors import (
    ServerRejectedTlsHandshake,
    ServerTlsConfigurationNotSupported,
    TlsHandshakeTimedOut,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuite
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


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
    """Initiates a TLS handshake with the server using the TLS version and the cipher suite specified."""
    ssl_connection = server_connectivity_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, openssl_version=cipher_suite.supported_by_openssl_version
    )

    # Set the cipher suite to test
    if tls_version == TlsVersionEnum.TLS_1_3:
        if not isinstance(ssl_connection.ssl_client, (SslClient_OpenSSL_1_1_1, SslClient_OpenSSL_4_0_0)):
            raise RuntimeError("Should never happen")

        # OpenSSL provides a dedicated method for setting TLS 1.3 cipher suites
        ssl_connection.ssl_client.set_ciphersuites(cipher_suite.openssl_name)
    else:
        try:
            ssl_connection.ssl_client.set_cipher_list(cipher_suite.openssl_name)
        except OpenSSLError as e:
            openssl_error_message = e.args[0]
            if "no cipher match" in openssl_error_message:
                # This error is raised when the cipher suite specified is not supported by the version of OpenSSL used
                raise NoCiphersAvailableBugInSSlyze()

            raise

    # Perform the TLS handshake
    ephemeral_key = None
    try:
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
