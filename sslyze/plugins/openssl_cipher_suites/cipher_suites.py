from dataclasses import dataclass, field

from nassl.base_ssl_client import TlsVersionEnum
from nassl.openssl_1_0_2.ssl_client import SslClient_OpenSSL_1_0_2
from nassl.openssl_1_1_1.ssl_client import SslClient_OpenSSL_1_1_1
from nassl.openssl_4_0_0.ssl_client import SslClient_OpenSSL_4_0_0

from sslyze.connection_helpers.tls_connection import OpenSslVersionEnum
from sslyze.plugins.openssl_cipher_suites._cipher_suites_rfc_names import (
    RFC_NAME_TO_KEY_SIZE_MAPPING,
    SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING,
    SSLV2_RFC_TO_OPENSSL_NAMES_MAPPING,
    TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    TLS_RFC_TO_OPENSSL_NAMES_MAPPING,
)


@dataclass(frozen=True)
class CipherSuite:
    name: str
    is_anonymous: bool
    key_size: int

    # OpenSSL uses a different naming convention than the corresponding RFCs, and also can have multiple names for
    # the same cipher suites; to avoid duplicates we use compare=False
    openssl_name: str = field(compare=False)

    # A version of OpenSSL available in nassl that definitely supports this cipher suite
    supported_by_openssl_version: OpenSslVersionEnum


_TLS_1_3_CIPHER_SUITES = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]


_ALL_PARSED_CIPHER_SUITES_BY_TLS_VERSION: dict[TlsVersionEnum, set[CipherSuite]] = {}


def retrieve_all_available_cipher_suites(tls_version: TlsVersionEnum) -> set[CipherSuite]:
    if tls_version in _ALL_PARSED_CIPHER_SUITES_BY_TLS_VERSION:
        return _ALL_PARSED_CIPHER_SUITES_BY_TLS_VERSION[tls_version]

    # Disable SRP and PSK cipher suites as they need a special setup in the client and are never used
    cipher_string = "ALL:COMPLEMENTOFALL:-PSK:-SRP"

    # Retrieve the list of supported cipher suites by each version of OpenSSL that's in nassl
    client_1_0_2_ciphers: list[str]
    client_1_1_1_ciphers: list[str]
    client_4_0_0_ciphers: list[str]
    if tls_version in [TlsVersionEnum.SSL_2_0, TlsVersionEnum.SSL_3_0]:
        client_1_0_2 = SslClient_OpenSSL_1_0_2(tls_version=tls_version)
        client_1_0_2.set_cipher_list(cipher_string)
        client_1_0_2_ciphers = client_1_0_2.get_cipher_list()

        client_1_1_1_ciphers = []
        client_4_0_0_ciphers = []

    elif tls_version in [TlsVersionEnum.TLS_1_0, TlsVersionEnum.TLS_1_1, TlsVersionEnum.TLS_1_2]:
        client_1_0_2 = SslClient_OpenSSL_1_0_2(tls_version=tls_version)
        client_1_0_2.set_cipher_list(cipher_string)
        client_1_0_2_ciphers = client_1_0_2.get_cipher_list()

        client_1_1_1 = SslClient_OpenSSL_1_1_1(tls_version=tls_version)
        client_1_1_1.set_cipher_list(cipher_string)
        client_1_1_1_ciphers = client_1_1_1.get_cipher_list()

        client_4_0_0 = SslClient_OpenSSL_4_0_0(tls_version=tls_version)
        client_4_0_0.set_cipher_list(cipher_string)
        client_4_0_0_ciphers = client_4_0_0.get_cipher_list()

    elif tls_version == TlsVersionEnum.TLS_1_3:
        # For TLS 1.3 we just hardcode OpenSSL 1.1.1
        client_1_0_2_ciphers = []
        client_1_1_1_ciphers = _TLS_1_3_CIPHER_SUITES
        client_4_0_0_ciphers = []
    else:
        raise ValueError(f"Unsupported TLS version: {tls_version}")

    # Make the OpenSSL -> RFC name conversion easy
    if tls_version == TlsVersionEnum.SSL_2_0:
        openssl_to_rfc_name_mappping = SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING
    else:
        openssl_to_rfc_name_mappping = TLS_OPENSSL_TO_RFC_NAMES_MAPPING

    # Deduplicate cipher suites that have multiple names in OpenSSL (ie. DHE-RSA-DES-CBC3-SHA and EDH-RSA-DES-CBC3-SHA)
    #  by using their RFC name as the unique identifier
    # Order is important : we prioritize the 4.0.0 client
    cipher_rfc_name_to_openssl_version: dict[str, OpenSslVersionEnum] = {}
    for cipher in client_1_0_2_ciphers:
        cipher_rfc_name = openssl_to_rfc_name_mappping.get(cipher, cipher)
        cipher_rfc_name_to_openssl_version[cipher_rfc_name] = OpenSslVersionEnum.OPENSSL_1_0_2
    for cipher in client_1_1_1_ciphers:
        cipher_rfc_name = openssl_to_rfc_name_mappping.get(cipher, cipher)
        cipher_rfc_name_to_openssl_version[cipher_rfc_name] = OpenSslVersionEnum.OPENSSL_1_1_1
    for cipher in client_4_0_0_ciphers:
        cipher_rfc_name = openssl_to_rfc_name_mappping.get(cipher, cipher)
        cipher_rfc_name_to_openssl_version[cipher_rfc_name] = OpenSslVersionEnum.OPENSSL_4_0_0

    # Make the RFC -> OpenSSL name conversion easy
    if tls_version == TlsVersionEnum.SSL_2_0:
        rfc_to_openssl_name_mappping = SSLV2_RFC_TO_OPENSSL_NAMES_MAPPING
    else:
        rfc_to_openssl_name_mappping = TLS_RFC_TO_OPENSSL_NAMES_MAPPING

    # Lastly, return the "parsed" cipher suites with all the relevant info
    all_parsed_cipher_suites = set()
    for cipher_suite_rfc_name, openssl_version in cipher_rfc_name_to_openssl_version.items():
        if tls_version == TlsVersionEnum.TLS_1_3:
            # For TLS 1.3, OpenSSL uses the RFC names, so we can skip the mapping
            cipher_suite_openssl_name = cipher_suite_rfc_name
        else:
            cipher_suite_openssl_name = rfc_to_openssl_name_mappping.get(cipher_suite_rfc_name, cipher_suite_rfc_name)

        parsed_suite = CipherSuite(
            name=cipher_suite_rfc_name,
            openssl_name=cipher_suite_openssl_name,
            is_anonymous="anon" in cipher_suite_rfc_name,
            key_size=RFC_NAME_TO_KEY_SIZE_MAPPING[cipher_suite_rfc_name],
            supported_by_openssl_version=openssl_version,
        )
        all_parsed_cipher_suites.add(parsed_suite)

    _ALL_PARSED_CIPHER_SUITES_BY_TLS_VERSION[tls_version] = all_parsed_cipher_suites

    return all_parsed_cipher_suites
