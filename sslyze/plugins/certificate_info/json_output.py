from base64 import b64encode
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

import pydantic
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import NameAttribute
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import ObjectIdentifier  # type: ignore
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from sslyze import (
    CertificateInfoExtraArgument,
    CertificateInfoScanResult,
    CertificateDeploymentAnalysisResult,
    PathValidationResult,
    TrustStore,
)
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.certificate_info._certificate_utils import (
    get_public_key_sha256,
    extract_dns_subject_alternative_names,
)


class _BaseModelWithOrmMode(pydantic.BaseModel):
    class Config:
        orm_mode = True


class CertificateInfoExtraArgumentAsJson(_BaseModelWithOrmMode):
    custom_ca_file: Path


CertificateInfoExtraArgumentAsJson.__doc__ = CertificateInfoExtraArgument.__doc__  # type: ignore


class _PublicKeyAsJson(_BaseModelWithOrmMode):
    algorithm: str
    key_size: Optional[int]  # None for Ed25519PublicKey and Ed448PublicKey

    # Only set if the algorithm is RSA
    rsa_e: Optional[int]
    rsa_n: Optional[int]

    # Only set if the algorithm is Elliptic Curve
    ec_curve_name: Optional[str]
    ec_x: Optional[int]
    ec_y: Optional[int]

    @classmethod
    def from_orm(cls, public_key: Any) -> "_PublicKeyAsJson":
        try:
            public_key_size = public_key.key_size  # type: ignore
        except AttributeError:
            public_key_size = None

        return cls(
            algorithm=public_key.__class__.__name__,
            key_size=public_key_size,
            # EC-only fields
            ec_curve_name=public_key.curve.name if isinstance(public_key, EllipticCurvePublicKey) else None,
            ec_x=public_key.public_numbers().x if isinstance(public_key, EllipticCurvePublicKey) else None,
            ec_y=public_key.public_numbers().y if isinstance(public_key, EllipticCurvePublicKey) else None,
            # RSA-only fields
            rsa_e=public_key.public_numbers().e if isinstance(public_key, RSAPublicKey) else None,
            rsa_n=public_key.public_numbers().n if isinstance(public_key, RSAPublicKey) else None,
        )


class _ObjectIdentifierAsJson(_BaseModelWithOrmMode):
    name: str
    dotted_string: str

    @classmethod
    def from_orm(cls, oid: ObjectIdentifier) -> "_ObjectIdentifierAsJson":
        return cls(name=oid._name, dotted_string=oid.dotted_string)


class _NameAttributeAsJson(_BaseModelWithOrmMode):
    oid: _ObjectIdentifierAsJson
    value: str
    rfc4514_string: str

    @classmethod
    def from_orm(cls, name_attribute: NameAttribute) -> "_NameAttributeAsJson":
        return cls(
            oid=_ObjectIdentifierAsJson.from_orm(name_attribute.oid),
            value=name_attribute.value,
            rfc4514_string=name_attribute.rfc4514_string(),
        )


class _X509NameAsJson(_BaseModelWithOrmMode):
    rfc4514_string: str
    attributes: List[_NameAttributeAsJson]

    @classmethod
    def from_orm(cls, name: x509.name.Name) -> "_X509NameAsJson":
        return cls(
            rfc4514_string=name.rfc4514_string(), attributes=[_NameAttributeAsJson.from_orm(attr) for attr in name]
        )


class _SubjAltNameAsJson(pydantic.BaseModel):
    dns: List[str]


class _HashAlgorithmAsJson(_BaseModelWithOrmMode):
    name: str
    digest_size: int

    @classmethod
    def from_orm(cls, hash_algorithm: hashes.HashAlgorithm) -> "_HashAlgorithmAsJson":
        return cls(name=hash_algorithm.name, digest_size=hash_algorithm.digest_size)


class _CertificateAsJson(_BaseModelWithOrmMode):
    as_pem: str
    hpkp_pin: str  # RFC 7469
    fingerprint_sha1: str
    fingerprint_sha256: str

    serial_number: int
    not_valid_before: datetime
    not_valid_after: datetime
    subject_alternative_name: _SubjAltNameAsJson

    # The signature_hash_algorithm can be None if signature did not use separate hash (ED25519, ED448)
    # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.signature_hash_algorithm
    signature_hash_algorithm: Optional[_HashAlgorithmAsJson]
    signature_algorithm_oid: _ObjectIdentifierAsJson

    # We may get garbage/invalid certificates that do not have a subject or an issuer, hence they can be None
    # https://github.com/nabla-c0d3/sslyze/issues/403
    subject: Optional[_X509NameAsJson]
    issuer: Optional[_X509NameAsJson]

    public_key: _PublicKeyAsJson

    @classmethod
    def from_orm(cls, certificate: x509.Certificate) -> "_CertificateAsJson":
        signature_hash_algorithm: Optional[_HashAlgorithmAsJson]
        if certificate.signature_hash_algorithm:
            signature_hash_algorithm = _HashAlgorithmAsJson.from_orm(certificate.signature_hash_algorithm)
        else:
            signature_hash_algorithm = None

        # We may get garbage/invalid certificates so we need to handle ValueErrors.
        # See https://github.com/nabla-c0d3/sslyze/issues/403 for more information
        subject_field: Optional[_X509NameAsJson]
        try:
            subject_field = _X509NameAsJson.from_orm(certificate.subject)
        except ValueError:
            subject_field = None

        issuer_field: Optional[_X509NameAsJson]
        try:
            issuer_field = _X509NameAsJson.from_orm(certificate.issuer)
        except ValueError:
            issuer_field = None

        return cls(
            as_pem=certificate.public_bytes(Encoding.PEM).decode("ascii"),
            hpkp_pin=b64encode(get_public_key_sha256(certificate)).decode("ascii"),
            fingerprint_sha1=b64encode(certificate.fingerprint(hashes.SHA1())).decode("ascii"),
            fingerprint_sha256=b64encode(certificate.fingerprint(hashes.SHA256())).decode("ascii"),
            serial_number=certificate.serial_number,
            not_valid_before=certificate.not_valid_before,
            not_valid_after=certificate.not_valid_after,
            subject_alternative_name=_SubjAltNameAsJson(dns=extract_dns_subject_alternative_names(certificate)),
            signature_hash_algorithm=signature_hash_algorithm,
            signature_algorithm_oid=certificate.signature_algorithm_oid,
            subject=subject_field,
            issuer=issuer_field,
            public_key=_PublicKeyAsJson.from_orm(certificate.public_key()),
        )


class _OcspResponseAsJson(_BaseModelWithOrmMode):
    response_status: str

    certificate_status: Optional[str]
    revocation_time: Optional[datetime]

    produced_at: Optional[datetime]
    this_update: Optional[datetime]
    next_update: Optional[datetime]

    serial_number: Optional[int]

    @classmethod
    def from_orm(cls, ocsp_response: x509.ocsp.OCSPResponse) -> "_OcspResponseAsJson":
        response_status = ocsp_response.response_status.name
        if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
            return cls(
                response_status=response_status,
                certificate_status=None,
                revocation_time=None,
                produced_at=None,
                this_update=None,
                next_update=None,
                serial_number=None,
            )
        else:
            return cls(
                response_status=response_status,
                certificate_status=ocsp_response.certificate_status.name,
                revocation_time=ocsp_response.revocation_time,
                produced_at=ocsp_response.produced_at,
                this_update=ocsp_response.this_update,
                next_update=ocsp_response.next_update,
                serial_number=ocsp_response.serial_number,
            )


class _TrustStoreAsJson(_BaseModelWithOrmMode):
    path: Path
    name: str
    version: str
    ev_oids: Optional[List[_ObjectIdentifierAsJson]]


_TrustStoreAsJson.__doc__ = TrustStore.__doc__  # type: ignore


class _PathValidationResultAsJson(_BaseModelWithOrmMode):
    trust_store: _TrustStoreAsJson
    verified_certificate_chain: Optional[List[_CertificateAsJson]]
    openssl_error_string: Optional[str]
    was_validation_successful: bool


_PathValidationResultAsJson.__doc__ = PathValidationResult.__doc__  # type: ignore


class _CertificateDeploymentAnalysisResultAsJson(_BaseModelWithOrmMode):
    received_certificate_chain: List[_CertificateAsJson]
    leaf_certificate_subject_matches_hostname: bool
    leaf_certificate_has_must_staple_extension: bool
    leaf_certificate_is_ev: bool
    leaf_certificate_signed_certificate_timestamps_count: Optional[int]
    received_chain_contains_anchor_certificate: Optional[bool]
    received_chain_has_valid_order: Optional[bool]

    path_validation_results: List[_PathValidationResultAsJson]
    verified_chain_has_sha1_signature: Optional[bool]
    verified_chain_has_legacy_symantec_anchor: Optional[bool]

    ocsp_response: Optional[_OcspResponseAsJson]
    ocsp_response_is_trusted: Optional[bool]

    verified_certificate_chain: Optional[List[_CertificateAsJson]]


_CertificateDeploymentAnalysisResultAsJson.__doc__ = CertificateDeploymentAnalysisResult.__doc__  # type: ignore


class CertificateInfoScanResultAsJson(_BaseModelWithOrmMode):
    hostname_used_for_server_name_indication: str
    certificate_deployments: List[_CertificateDeploymentAnalysisResultAsJson]


CertificateInfoScanResultAsJson.__doc__ = CertificateInfoScanResult.__doc__  # type: ignore


class CertificateInfoScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[CertificateInfoScanResultAsJson]
