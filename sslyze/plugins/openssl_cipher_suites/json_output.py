from base64 import b64encode
from typing import List, Optional, Any

from nassl.ephemeral_key_info import EphemeralKeyInfo, EcDhEphemeralKeyInfo, NistEcDhKeyExchangeInfo, DhEphemeralKeyInfo
from pydantic import model_validator
from sslyze.json.pydantic_utils import BaseModelWithOrmMode, StrFromEnumValueName
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.openssl_cipher_suites.implementation import (
    CipherSuitesScanResult,
    CipherSuiteAcceptedByServer,
)


class _CipherSuiteAsJson(BaseModelWithOrmMode):
    name: str
    is_anonymous: bool
    key_size: int
    openssl_name: str


_Base64EncodedBytes = str


class _EphemeralKeyInfoAsJson(BaseModelWithOrmMode):
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

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, EphemeralKeyInfo):
            return data

        key_info: EphemeralKeyInfo = data
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

        return dict(
            type_name=key_info.type_name,
            size=key_info.size,
            public_bytes=b64encode(key_info.public_bytes).decode("utf-8"),
            curve_name=curve_name,
            x=x,
            y=y,
            prime=prime,
            generator=generator,
        )


class _CipherSuiteAcceptedByServerAsJson(BaseModelWithOrmMode):
    cipher_suite: _CipherSuiteAsJson
    ephemeral_key: Optional[_EphemeralKeyInfoAsJson]


assert CipherSuiteAcceptedByServer.__doc__
_CipherSuiteAcceptedByServerAsJson.__doc__ = CipherSuiteAcceptedByServer.__doc__


class _CipherSuiteRejectedByServerAsJson(BaseModelWithOrmMode):
    cipher_suite: _CipherSuiteAsJson
    error_message: str


class CipherSuitesScanResultAsJson(BaseModelWithOrmMode):
    tls_version_used: StrFromEnumValueName
    is_tls_version_supported: bool

    accepted_cipher_suites: List[_CipherSuiteAcceptedByServerAsJson]
    rejected_cipher_suites: List[_CipherSuiteRejectedByServerAsJson]


assert CipherSuitesScanResult.__doc__
CipherSuitesScanResultAsJson.__doc__ = CipherSuitesScanResult.__doc__


class CipherSuitesScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[CipherSuitesScanResultAsJson]
