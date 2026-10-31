from base64 import b64encode
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, Name, NameAttribute, ObjectIdentifier, ocsp
from pydantic import BaseModel, model_validator

from sslyze import (
    CertificateDeploymentAnalysisResult,
    CertificateInfoExtraArgument,
    CertificateInfoScanResult,
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
    key_size: int | None  # None for Ed25519PublicKey and Ed448PublicKey

    # Only set if the algorithm is RSA
    rsa_e: int | None
    rsa_n: int | None

    # Only set if the algorithm is Elliptic Curve
    ec_curve_name: str | None
    ec_x: int | None
    ec_y: int | None

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

        return {
            "algorithm": public_key.__class__.__name__,
            "key_size": public_key_size,
            # EC-only fields
            "ec_curve_name": public_key.curve.name if isinstance(public_key, EllipticCurvePublicKey) else None,
            "ec_x": public_key.public_numbers().x if isinstance(public_key, EllipticCurvePublicKey) else None,
            "ec_y": public_key.public_numbers().y if isinstance(public_key, EllipticCurvePublicKey) else None,
            # RSA-only fields
            "rsa_e": public_key.public_numbers().e if isinstance(public_key, RSAPublicKey) else None,
            "rsa_n": public_key.public_numbers().n if isinstance(public_key, RSAPublicKey) else None,
        }


class _ObjectIdentifierAsJson(BaseModelWithOrmMode):
    name: str
    dotted_string: str

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, ObjectIdentifier):
            return data

        oid: ObjectIdentifier = data
        return {
            "name": oid._name,  # type: ignore
            "dotted_string": oid.dotted_string,
        }


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
        return {
            "oid": name_attribute.oid,
            "value": name_attribute.value if isinstance(name_attribute.value, str) else str(name_attribute.value),
            "rfc4514_string": name_attribute.rfc4514_string(),
        }


class _X509NameAsJson(BaseModelWithOrmMode):
    rfc4514_string: str
    attributes: list[_NameAttributeAsJson]

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, Name):
            return data

        name: Name = data
        return {"rfc4514_string": name.rfc4514_string(), "attributes": [attr for attr in name]}


class _SubjAltNameAsJson(BaseModel):
    dns_names: list[str]
    ip_addresses: list[str] = []


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
    signature_hash_algorithm: _HashAlgorithmAsJson | None
    signature_algorithm_oid: _ObjectIdentifierAsJson

    # We may get garbage/invalid certificates that do not have a subject or an issuer, hence they can be None
    # https://github.com/nabla-c0d3/sslyze/issues/403
    subject: _X509NameAsJson | None
    issuer: _X509NameAsJson | None

    public_key: _PublicKeyAsJson

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, data: Any) -> Any:
        if not isinstance(data, Certificate):
            return data

        certificate: Certificate = data

        # We may get garbage/invalid certificates so we need to handle ValueErrors.
        # See https://github.com/nabla-c0d3/sslyze/issues/403 for more information
        subject_field: Name | None
        try:
            subject_field = certificate.subject
        except ValueError:
            subject_field = None

        issuer_field: Name | None
        try:
            issuer_field = certificate.issuer
        except ValueError:
            issuer_field = None

        subj_alt_name_ext = parse_subject_alternative_name_extension(certificate)

        return {
            "as_pem": certificate.public_bytes(Encoding.PEM).decode("ascii"),
            "hpkp_pin": b64encode(get_public_key_sha256(certificate)).decode("ascii"),
            "fingerprint_sha1": b64encode(certificate.fingerprint(hashes.SHA1())).decode("ascii"),
            "fingerprint_sha256": b64encode(certificate.fingerprint(hashes.SHA256())).decode("ascii"),
            "serial_number": certificate.serial_number,
            "not_valid_before": certificate.not_valid_before_utc,
            "not_valid_after": certificate.not_valid_after_utc,
            "subject_alternative_name": _SubjAltNameAsJson(
                dns_names=subj_alt_name_ext.dns_names,
                ip_addresses=subj_alt_name_ext.ip_addresses,
            ),
            "signature_hash_algorithm": certificate.signature_hash_algorithm,
            "signature_algorithm_oid": certificate.signature_algorithm_oid,
            "subject": subject_field,
            "issuer": issuer_field,
            "public_key": certificate.public_key(),
        }


class _OcspResponseAsJson(BaseModelWithOrmMode):
    response_status: StrFromEnumValueName

    certificate_status: StrFromEnumValueName | None
    revocation_time: datetime | None

    produced_at: datetime | None
    this_update: datetime | None
    next_update: datetime | None

    serial_number: int | None

    @model_validator(mode="before")
    @classmethod
    def _handle_object(cls, ocsp_response: ocsp.OCSPResponse) -> Any:
        if not isinstance(ocsp_response, ocsp.OCSPResponse):
            return ocsp_response

        response_status = ocsp_response.response_status.name
        if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return {
                "response_status": response_status,
                "certificate_status": None,
                "revocation_time": None,
                "produced_at": None,
                "this_update": None,
                "next_update": None,
                "serial_number": None,
            }
        return {
            "response_status": response_status,
            "certificate_status": ocsp_response.certificate_status,
            "revocation_time": ocsp_response.revocation_time_utc,
            "produced_at": ocsp_response.produced_at_utc,
            "this_update": ocsp_response.this_update_utc,
            "next_update": ocsp_response.next_update_utc,
            "serial_number": ocsp_response.serial_number,
        }


class _TrustStoreAsJson(BaseModelWithOrmMode):
    path: Path
    name: str
    version: str
    ev_oids: list[_ObjectIdentifierAsJson] | None


assert TrustStore.__doc__
_TrustStoreAsJson.__doc__ = TrustStore.__doc__


class _PathValidationResultAsJson(BaseModelWithOrmMode):
    trust_store: _TrustStoreAsJson
    verified_certificate_chain: list[_CertificateAsJson] | None
    validation_error: str | None
    was_validation_successful: bool


assert PathValidationResult.__doc__
_PathValidationResultAsJson.__doc__ = PathValidationResult.__doc__


class _CertificateDeploymentAnalysisResultAsJson(BaseModelWithOrmMode):
    received_certificate_chain: list[_CertificateAsJson]
    leaf_certificate_has_must_staple_extension: bool
    leaf_certificate_is_ev: bool
    leaf_certificate_signed_certificate_timestamps_count: int | None
    received_chain_contains_anchor_certificate: bool | None
    received_chain_has_valid_order: bool | None

    path_validation_results: list[_PathValidationResultAsJson]
    verified_chain_has_sha1_signature: bool | None
    verified_chain_has_legacy_symantec_anchor: bool | None

    ocsp_response: _OcspResponseAsJson | None
    ocsp_response_is_trusted: bool | None

    verified_certificate_chain: list[_CertificateAsJson] | None


assert CertificateDeploymentAnalysisResult.__doc__
_CertificateDeploymentAnalysisResultAsJson.__doc__ = CertificateDeploymentAnalysisResult.__doc__


class CertificateInfoScanResultAsJson(BaseModelWithOrmMode):
    hostname_used_for_server_name_indication: str
    certificate_deployments: list[_CertificateDeploymentAnalysisResultAsJson]

    # Default argument for backward compatibility as this field was added in v6.2.0
    certificate_deployment_with_sni_disabled: _CertificateDeploymentAnalysisResultAsJson | None = None


assert CertificateInfoScanResult.__doc__
CertificateInfoScanResultAsJson.__doc__ = CertificateInfoScanResult.__doc__


class CertificateInfoScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: CertificateInfoScanResultAsJson | None
