from dataclasses import field
from typing import Dict, Set

from dataclasses import dataclass

from nassl.openssl_1_0_2.ssl_client import SslClient_OpenSSL_1_0_2
from nassl.base_ssl_client import TlsVersionEnum
from nassl.openssl_1_1_1.ssl_client import SslClient_OpenSSL_1_1_1

from sslyze.plugins.openssl_cipher_suites._cipher_suites_rfc_names import (
    OPENSSL_TO_RFC_NAMES_MAPPING,
    RFC_NAME_TO_KEY_SIZE_MAPPING,
)


@dataclass(frozen=True)
class CipherSuite:
    name: str
    is_anonymous: bool
    key_size: int
    # OpenSSL uses a different naming convention than the corresponding RFCs, and also can have multiple names for
    # the same cipher suites; to avoid duplicates we use compare=False
    openssl_name: str = field(compare=False)


# TLS 1.3 cipher suites implemented in OpenSSL 1.1.1
_TLS_1_3_CIPHER_SUITES = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_CCM_8_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]


def _parse_all_cipher_suites_with_legacy_openssl(tls_version: TlsVersionEnum) -> Set[str]:
    ssl_client = SslClient_OpenSSL_1_0_2(tls_version=TlsVersionEnum(tls_version.value))
    # Disable SRP and PSK cipher suites as they need a special setup in the client and are never used
    ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
    return set(ssl_client.get_cipher_list())


def _parse_all_cipher_suites() -> Dict[TlsVersionEnum, Set[CipherSuite]]:
    tls_version_to_cipher_suites: Dict[TlsVersionEnum, Set[CipherSuite]] = {}

    for tls_version in [
        TlsVersionEnum.SSL_2_0,
        TlsVersionEnum.SSL_3_0,
        TlsVersionEnum.TLS_1_0,
        TlsVersionEnum.TLS_1_1,
    ]:
        openssl_cipher_strings = _parse_all_cipher_suites_with_legacy_openssl(tls_version)
        tls_version_to_cipher_suites[tls_version] = set()
        for cipher_suite_openssl_name in openssl_cipher_strings:
            cipher_suite_rfc_name = OPENSSL_TO_RFC_NAMES_MAPPING[tls_version][cipher_suite_openssl_name]
            tls_version_to_cipher_suites[tls_version].add(
                CipherSuite(
                    name=cipher_suite_rfc_name,
                    openssl_name=cipher_suite_openssl_name,
                    is_anonymous=True if "anon" in cipher_suite_rfc_name else False,
                    key_size=RFC_NAME_TO_KEY_SIZE_MAPPING[cipher_suite_rfc_name],
                )
            )

    # For TLS 1.2, we have to use both the legacy and modern OpenSSL to cover all cipher suites
    cipher_suites_from_legacy_openssl = _parse_all_cipher_suites_with_legacy_openssl(TlsVersionEnum.TLS_1_2)

    ssl_client_modern = SslClient_OpenSSL_1_1_1(tls_version=TlsVersionEnum(TlsVersionEnum.TLS_1_2.value))
    ssl_client_modern.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
    cipher_suites_from_modern_openssl = set(ssl_client_modern.get_cipher_list())

    # Combine the two sets of cipher suites
    openssl_cipher_strings = cipher_suites_from_legacy_openssl.union(cipher_suites_from_modern_openssl)
    tls_version_to_cipher_suites[TlsVersionEnum.TLS_1_2] = set()
    for cipher_suite_openssl_name in openssl_cipher_strings:
        # Ignore TLS 1.3 cipher suites
        if cipher_suite_openssl_name in _TLS_1_3_CIPHER_SUITES:
            continue

        # Ignore cipher suite that is defined twice in OpenSSLL DHE-RSA-DES-CBC3-SHA and EDH-RSA-DES-CBC3-SHA
        if cipher_suite_openssl_name == "EDH-RSA-DES-CBC3-SHA":
            continue

        cipher_suite_rfc_name = OPENSSL_TO_RFC_NAMES_MAPPING[TlsVersionEnum.TLS_1_2][cipher_suite_openssl_name]
        tls_version_to_cipher_suites[TlsVersionEnum.TLS_1_2].add(
            CipherSuite(
                name=cipher_suite_rfc_name,
                openssl_name=cipher_suite_openssl_name,
                is_anonymous=True if "anon" in cipher_suite_rfc_name else False,
                key_size=RFC_NAME_TO_KEY_SIZE_MAPPING[cipher_suite_rfc_name],
            )
        )

    # TLS 1.3 - the list is just hardcoded
    tls_version_to_cipher_suites[TlsVersionEnum.TLS_1_3] = {
        CipherSuite(
            # For TLS 1.3 OpenSSL started using the official names
            name=cipher_suite_name,
            openssl_name=cipher_suite_name,
            is_anonymous=False,
            key_size=RFC_NAME_TO_KEY_SIZE_MAPPING[cipher_suite_name],
        )
        for cipher_suite_name in _TLS_1_3_CIPHER_SUITES
    }

    return tls_version_to_cipher_suites


class CipherSuitesRepository:
    # Pre-parse all the available cipher suites
    _ALL_CIPHER_SUITES = _parse_all_cipher_suites()

    @classmethod
    def get_all_cipher_suites(cls, tls_version: TlsVersionEnum) -> Set[CipherSuite]:
        """Get the list of cipher suites supported by OpenSSL for the given SSL/TLS version."""
        return cls._ALL_CIPHER_SUITES[tls_version]

    @classmethod
    def get_cipher_suite_with_openssl_name(cls, tls_version: TlsVersionEnum, openssl_name: str) -> CipherSuite:
        for cipher_suite in cls.get_all_cipher_suites(tls_version):
            if cipher_suite.openssl_name == openssl_name:
                return cipher_suite
        raise ValueError(f"Could not find a cipher suite with the supplied name: {openssl_name}")
