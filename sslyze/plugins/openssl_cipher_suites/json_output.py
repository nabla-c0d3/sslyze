from base64 import b64encode
from typing import List, Optional

import pydantic
from nassl.ephemeral_key_info import EphemeralKeyInfo, EcDhEphemeralKeyInfo, NistEcDhKeyExchangeInfo, DhEphemeralKeyInfo

from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.openssl_cipher_suites.implementation import (
    CipherSuitesScanResult,
    CipherSuiteAcceptedByServer,
)


class _BaseModelWithOrmMode(pydantic.BaseModel):
    class Config:
        orm_mode = True
        extra = "forbid"  # Fields must match between the JSON representation and the result objects


class _CipherSuiteAsJson(_BaseModelWithOrmMode):
    name: str
    is_anonymous: bool
    key_size: int
    openssl_name: str


_Base64EncodedBytes = str


class _EphemeralKeyInfoAsJson(_BaseModelWithOrmMode):
    type_name: str
    size: int
    public_bytes: _Base64EncodedBytes

    # ECDH
    curve_name: Optional[str] = None

    # Nist ECDH
    x: Optional[_Base64EncodedBytes] = None
    y: Optional[_Base64EncodedBytes] = None

    # DH
    prime: Optional[_Base64EncodedBytes] = None
    generator: Optional[_Base64EncodedBytes] = None

    @classmethod
    def from_orm(cls, key_info: EphemeralKeyInfo) -> "_EphemeralKeyInfoAsJson":
        curve_name: Optional[str] = None
        x: Optional[_Base64EncodedBytes] = None
        y: Optional[_Base64EncodedBytes] = None
        prime: Optional[_Base64EncodedBytes] = None
        generator: Optional[_Base64EncodedBytes] = None

        if isinstance(key_info, EcDhEphemeralKeyInfo):
            curve_name = key_info.curve_name

        if isinstance(key_info, NistEcDhKeyExchangeInfo):
            x = b64encode(key_info.x).decode("utf-8")
            y = b64encode(key_info.y).decode("utf-8")

        if isinstance(key_info, DhEphemeralKeyInfo):
            prime = b64encode(key_info.prime).decode("utf-8")
            generator = b64encode(key_info.generator).decode("utf-8")

        return cls(
            type_name=key_info.type_name,
            size=key_info.size,
            public_bytes=b64encode(key_info.public_bytes).decode("utf-8"),
            curve_name=curve_name,
            x=x,
            y=y,
            prime=prime,
            generator=generator,
        )


class _CipherSuiteAcceptedByServerAsJson(_BaseModelWithOrmMode):
    cipher_suite: _CipherSuiteAsJson
    ephemeral_key: Optional[_EphemeralKeyInfoAsJson]


_CipherSuiteAcceptedByServerAsJson.__doc__ = CipherSuiteAcceptedByServer.__doc__  # type: ignore


class _CipherSuiteRejectedByServerAsJson(_BaseModelWithOrmMode):
    cipher_suite: _CipherSuiteAsJson
    error_message: str


class CipherSuitesScanResultAsJson(_BaseModelWithOrmMode):
    tls_version_used: str
    is_tls_version_supported: bool

    accepted_cipher_suites: List[_CipherSuiteAcceptedByServerAsJson]
    rejected_cipher_suites: List[_CipherSuiteRejectedByServerAsJson]

    @classmethod
    def from_orm(cls, scan_result: CipherSuitesScanResult) -> "CipherSuitesScanResultAsJson":
        return cls(
            tls_version_used=scan_result.tls_version_used.name,
            is_tls_version_supported=scan_result.is_tls_version_supported,
            accepted_cipher_suites=scan_result.accepted_cipher_suites,
            rejected_cipher_suites=scan_result.rejected_cipher_suites,
        )


CipherSuitesScanResultAsJson.__doc__ = CipherSuitesScanResult.__doc__  # type: ignore


class CipherSuitesScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[CipherSuitesScanResultAsJson]
