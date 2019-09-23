import random
import socket
from pathlib import Path
from typing import Optional

from nassl.legacy_ssl_client import LegacySslClient

from sslyze.server_setting import ServerNetworkLocation, ServerNetworkLocationViaDirectConnection, \
    ServerNetworkLocationViaHttpProxy, ServerNetworkConfiguration
from sslyze.utils.http_response_parser import HttpResponseParser

import time

from nassl import _nassl
from nassl.ssl_client import SslClient, OpenSslVersionEnum, BaseSslClient, OpenSslVerifyEnum
from nassl.ssl_client import ClientCertificateRequested

from sslyze.utils.tls_wrapped_protocol_helpers import TlsWrappedProtocolHelper, XmppHelper, XmppServerHelper, \
    START_TLS_HELPER_CLASSES


def _open_socket_for_direct_connection(
    server_location: ServerNetworkLocationViaDirectConnection,
    network_timeout: int
) -> socket.socket:
    return socket.create_connection((server_location.ip_address, server_location.port), timeout=network_timeout)


class ProxyConnectivityError(Exception):
    """The proxy was offline or did not return HTTP 200 to our CONNECT request.
    """


def _open_socket_for_connection_via_http_proxy(
    server_location: ServerNetworkLocationViaHttpProxy,
    network_timeout: int
) -> socket.socket:
    try:
        sock = socket.create_connection(
            (server_location.http_proxy_settings.hostname, server_location.http_proxy_settings.port),
            timeout=network_timeout
        )
    except socket.timeout as e:
        raise ProxyConnectivityError(f"Could not connect to the proxy: {str(e)}")
    except socket.error as e:
        raise ProxyConnectivityError(f"Could not connect to the proxy: {str(e)}")

    # Send a CONNECT request with the host we want to tunnel to
    proxy_authorization_header = server_location.http_proxy_settings.proxy_authorization_header
    if proxy_authorization_header is None:
        sock.send(f"CONNECT {server_location.hostname}:{server_location.port} HTTP/1.1\r\n\r\n".encode("utf-8"))
    else:
        sock.send(
            f"CONNECT {server_location.hostname}:{server_location.port} HTTP/1.1\r\n"
            f"Proxy-Authorization: Basic {proxy_authorization_header}\r\n\r\n".encode("utf-8")
        )
    http_response = HttpResponseParser.parse_from_socket(sock)

    # Check if the proxy was able to connect to the host
    if http_response.status != 200:
        raise ProxyConnectivityError(
            f"The proxy rejected the CONNECT request for {server_location.hostname}:{server_location.port}"
        )

    return sock


def _open_socket(server_location: ServerNetworkLocation, network_timeout: int) -> socket.socket:
    if isinstance(server_location, ServerNetworkLocationViaHttpProxy):
        return _open_socket_for_connection_via_http_proxy(server_location, network_timeout)
    elif isinstance(server_location, ServerNetworkLocationViaDirectConnection):
        return _open_socket_for_direct_connection(server_location, network_timeout)
    else:
        raise ValueError()


class SslHandshakeRejected(IOError):
    """The server explicitly rejected the SSL handshake.
    """

# The following errors mean that the server explicitly rejected the handshake. The goal to differentiate rejected
# handshakes from random network errors such as the server going offline, etc.
_HANDSHAKE_REJECTED_SOCKET_ERRORS = {
    "Nassl SSL handshake failed": "Unexpected EOF",
    "was forcibly closed": "Received FIN",
    "reset by peer": "Received RST",
}

_HANDSHAKE_REJECTED_SSL_ERRORS = {
    "excessive message size": "Excessive message size",
    "bad mac decode": "Bad mac decode",
    "wrong version number": "Wrong version number",
    "no cipher match": "No cipher match",
    "bad decompression": "Bad decompression",
    "peer error no cipher": "Peer error no cipher",
    "no cipher list": "No ciphers list",
    "insufficient security": "Insufficient security",
    "block type is not 01": "block type is not 01",  # Actually an RSA error
    "wrong ssl version": "Wrong SSL version",
    "sslv3 alert handshake failure": "Alert: handshake failure",
    "tlsv1 alert protocol version": "Alert: protocol version ",
    "tlsv1 alert decrypt error": "Alert: Decrypt error",
    "tlsv1 alert decode error": "Alert: Decode error",
    # The following issues have nothing to do with the server or the connection
    # They are client-side (SSLyze) issues
    # This one is returned by OpenSSL when a cipher set via set_cipher_list() is not
    # actually supported
    "no ciphers available": "No ciphers available",
    # This one is when OpenSSL rejects DH parameters (to protect against Logjam)
    "dh key too small": "DH Key too small",
}


class SslConnection:
    """SSL connection that handles error processing, including retries when receiving timeouts.

    This it the base class to use to connect to a server in order to scan it.
    """

    def __init__(
        self,
        server_location: ServerNetworkLocation,
        network_configuration: ServerNetworkConfiguration,
        tls_version: OpenSslVersionEnum,
        should_ignore_client_auth: bool,
        should_use_legacy_openssl: Optional[bool] = None,
        ca_certificates_path: Optional[Path] = None,
    ) -> None:
        self._server_location = server_location
        self._network_configuration = network_configuration

        # Create the StartTLS helper
        self._start_tls_helper: TlsWrappedProtocolHelper
        start_tls_helper_cls = START_TLS_HELPER_CLASSES[self._network_configuration.tls_wrapped_protocol]
        if start_tls_helper_cls in [XmppHelper, XmppServerHelper]:
            self._start_tls_helper = start_tls_helper_cls(
                server_hostname=self._server_location.hostname, xmpp_to=self._network_configuration.xmpp_to_hostname
            )
        else:
            self._start_tls_helper = start_tls_helper_cls(server_hostname=self._server_location.hostname)

        # Create the SSL client
        self.ssl_client: BaseSslClient
        # For older versions of TLS/SSL, we have to use a legacy OpenSSL
        if should_use_legacy_openssl is None:
            # For older versions of TLS/SSL, we have to use a legacy OpenSSL
            final_should_use_legacy_openssl = (
                False if tls_version in [OpenSslVersionEnum.TLSV1_2, OpenSslVersionEnum.TLSV1_3] else True
            )
        else:
            final_should_use_legacy_openssl = should_use_legacy_openssl
        ssl_client_cls = LegacySslClient if final_should_use_legacy_openssl else SslClient

        if network_configuration.tls_client_auth_credentials:
            # A client certificate and private key were provided
            self.ssl_client = ssl_client_cls(
                ssl_version=tls_version,
                ssl_verify=OpenSslVerifyEnum.NONE,
                ssl_verify_locations=str(ca_certificates_path) if ca_certificates_path else None,
                client_certchain_file=str(network_configuration.tls_client_auth_credentials.certificate_chain_path),
                client_key_file=str(network_configuration.tls_client_auth_credentials.key_path),
                client_key_type=network_configuration.tls_client_auth_credentials.key_type,
                client_key_password=network_configuration.tls_client_auth_credentials.key_password,
                ignore_client_authentication_requests=False,
            )
        else:
            # No client cert and key
            self.ssl_client = ssl_client_cls(
                ssl_version=tls_version,
                ssl_verify=OpenSslVerifyEnum.NONE,
                ssl_verify_locations=str(ca_certificates_path) if ca_certificates_path else None,
                ignore_client_authentication_requests=should_ignore_client_auth,
            )

        # Add Server Name Indication
        if tls_version != OpenSslVersionEnum.SSLV2:
            self.ssl_client.set_tlsext_host_name(network_configuration.tls_server_name_indication)

        # And a default cipher list to make the client hello smaller so we don't run into
        # https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=665452
        self.ssl_client.set_cipher_list("HIGH:MEDIUM:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA")

    def do_pre_handshake(self) -> None:
        # Open a socket to the server
        sock = _open_socket(self._server_location, self._network_configuration.timeout)
        self._start_tls_helper.prepare_socket_for_tls_handshake(sock)

        # Pass the connected socket to the SSL client
        self.ssl_client.set_underlying_socket(sock)

    def connect(self) -> None:
        retry_attempts = 0
        delay = 0

        # First try to connect to the server, and do retries if there are timeouts
        while True:
            # Sleep if it's a retry attempt
            time.sleep(delay)
            try:
                self.do_pre_handshake()

            except socket.timeout:
                # Attempt to retry connection if a network error occurred during connection or the handshake
                retry_attempts += 1
                if retry_attempts >= self._network_configuration.max_connection_attempts:
                    # Exhausted the number of retry attempts, give up
                    raise
                elif retry_attempts == 1:
                    delay = int(random.random())
                else:
                    # Exponential back off
                    delay = min(6, 2 * delay)  # Cap max delay at 6 seconds

            else:
                # No network error occurred
                break

        # After successfully connecting to the server, perform the TLS handshake
        try:
            self.ssl_client.do_handshake()

        except ClientCertificateRequested:
            # Server expected a client certificate and we didn't provide one
            raise
        except socket.timeout:
            # Network timeout, propagate the error
            raise
        except socket.error as e:
            for error_msg in _HANDSHAKE_REJECTED_SOCKET_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SslHandshakeRejected("TCP / " + _HANDSHAKE_REJECTED_SOCKET_ERRORS[error_msg])

            # Unknown socket error
            raise
        except _nassl.OpenSSLError as e:
            for error_msg in _HANDSHAKE_REJECTED_SSL_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SslHandshakeRejected("TLS / " + _HANDSHAKE_REJECTED_SSL_ERRORS[error_msg])
            raise  # Unknown SSL error if we get there

    def close(self) -> None:
        self.ssl_client.shutdown()

    def send_sample_request(self) -> str:
        return self._start_tls_helper.send_sample_request(self.ssl_client)
