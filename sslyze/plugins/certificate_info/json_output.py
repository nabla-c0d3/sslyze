from base64 import b64encode
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

from pydantic import BaseModel, model_validator


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import NameAttribute, ObjectIdentifier, Name, Certificate
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from sslyze import (
    CertificateInfoExtraArgument,
    CertificateInfoScanResult,
    CertificateDeploymentAnalysisResult,
    PathValidationResult,
    TrustStore,
)
from sslyze.json.pydantic_utils import BaseModelWithOrmMode, StrFromEnumValueName
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.certificate_info._certificate_utils import (
    get_public_key_sha256,
    parse_subject_alternative_name_extension,
)


class CertificateInfoExtraArgumentAsJson(BaseModelWithOrmMode):
    custom_ca_file: Path


assert CertificateInfoExtraArgument.__doc__
CertificateInfoExtraArgumentAsJson.__doc__ = CertificateInfoExtraArgument.__doc__


class _PublicKeyAsJson(BaseModelWithOrmMode):
    algorithm: str
    key_size: Optional[int]  # None for Ed25519PublicKey and Ed448PublicKey

    # Only set if the algorithm is RSA
    rsa_e: Optional[int]
    rsa_n: Optional[int]

    # Only set if the algorithm is Elliptic Curve
    ec_curve_name: Optional[str]
    ec_x: Optional[int]
    ec_y: Optional[int]

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return data

        # Assuming a cryptography.PublicKey
        public_key = data
        try:
            public_key_size = public_key.key_size  # type: ignore
        except AttributeError:
            public_key_size = None

        return dict(
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


class _ObjectIdentifierAsJson(BaseModelWithOrmMode):
    name: str
    dotted_string: str

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, ObjectIdentifier):
            return data

        oid: ObjectIdentifier = data
        return dict(
            name=oid._name,  # type: ignore
            dotted_string=oid.dotted_string,
        )


class _NameAttributeAsJson(BaseModelWithOrmMode):
    oid: _ObjectIdentifierAsJson
    value: str
    rfc4514_string: str

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, NameAttribute):
            return data

        name_attribute: NameAttribute = data
        return dict(
            oid=name_attribute.oid,
            value=name_attribute.value if isinstance(name_attribute.value, str) else str(name_attribute.value),
            rfc4514_string=name_attribute.rfc4514_string(),
        )


class _X509NameAsJson(BaseModelWithOrmMode):
    rfc4514_string: str
    attributes: List[_NameAttributeAsJson]

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, Name):
            return data

        name: Name = data
        return dict(rfc4514_string=name.rfc4514_string(), attributes=[attr for attr in name])


class _SubjAltNameAsJson(BaseModel):
    dns_names: List[str]
    ip_addresses: List[str] = []


class _HashAlgorithmAsJson(BaseModelWithOrmMode):
    name: StrFromEnumValueName
    digest_size: int


class _CertificateAsJson(BaseModelWithOrmMode):
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

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, Certificate):
            return data

        certificate: Certificate = data

        # We may get garbage/invalid certificates so we need to handle ValueErrors.
        # See https://github.com/nabla-c0d3/sslyze/issues/403 for more information
        subject_field: Optional[Name]
        try:
            subject_field = certificate.subject
        except ValueError:
            subject_field = None

        issuer_field: Optional[Name]
        try:
            issuer_field = certificate.issuer
        except ValueError:
            issuer_field = None

        subj_alt_name_ext = parse_subject_alternative_name_extension(certificate)

        return dict(
            as_pem=certificate.public_bytes(Encoding.PEM).decode("ascii"),
            hpkp_pin=b64encode(get_public_key_sha256(certificate)).decode("ascii"),
            fingerprint_sha1=b64encode(certificate.fingerprint(hashes.SHA1())).decode("ascii"),
            fingerprint_sha256=b64encode(certificate.fingerprint(hashes.SHA256())).decode("ascii"),
            serial_number=certificate.serial_number,
            not_valid_before=certificate.not_valid_before_utc,
            not_valid_after=certificate.not_valid_after_utc,
            subject_alternative_name=_SubjAltNameAsJson(
                dns_names=subj_alt_name_ext.dns_names,
                ip_addresses=subj_alt_name_ext.ip_addresses,
            ),
            signature_hash_algorithm=certificate.signature_hash_algorithm,
            signature_algorithm_oid=certificate.signature_algorithm_oid,
            subject=subject_field,
            issuer=issuer_field,
            public_key=certificate.public_key(),
        )


class _OcspResponseAsJson(BaseModelWithOrmMode):
    response_status: StrFromEnumValueName

    certificate_status: Optional[StrFromEnumValueName]
    revocation_time: Optional[datetime]

    produced_at: Optional[datetime]
    this_update: Optional[datetime]
    next_update: Optional[datetime]

    serial_number: Optional[int]


class _TrustStoreAsJson(BaseModelWithOrmMode):
    path: Path
    name: str
    version: str
    ev_oids: Optional[List[_ObjectIdentifierAsJson]]


assert TrustStore.__doc__
_TrustStoreAsJson.__doc__ = TrustStore.__doc__


class _PathValidationResultAsJson(BaseModelWithOrmMode):
    trust_store: _TrustStoreAsJson
    verified_certificate_chain: Optional[List[_CertificateAsJson]]
    validation_error: Optional[str]
    was_validation_successful: bool


assert PathValidationResult.__doc__
_PathValidationResultAsJson.__doc__ = PathValidationResult.__doc__


class _CertificateDeploymentAnalysisResultAsJson(BaseModelWithOrmMode):
    received_certificate_chain: List[_CertificateAsJson]
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


assert CertificateDeploymentAnalysisResult.__doc__
_CertificateDeploymentAnalysisResultAsJson.__doc__ = CertificateDeploymentAnalysisResult.__doc__


class CertificateInfoScanResultAsJson(BaseModelWithOrmMode):
    hostname_used_for_server_name_indication: str
    certificate_deployments: List[_CertificateDeploymentAnalysisResultAsJson]


assert CertificateInfoScanResult.__doc__
CertificateInfoScanResultAsJson.__doc__ = CertificateInfoScanResult.__doc__


class CertificateInfoScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[CertificateInfoScanResultAsJson]
