"""JSON serialization logic for objects only returned by the certificate info plugin.
"""
from base64 import b64encode
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.ocsp import _OCSPResponse
from cryptography.hazmat.backends.openssl.x509 import _Certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.ocsp import OCSPResponseStatus, load_der_ocsp_response
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from sslyze.plugins.certificate_info._certificate_utils import (
    get_public_key_sha256,
    extract_dns_subject_alternative_names,
)


def _monkeypatch_to_fix_certificate_asdict() -> None:
    # H4ck: monkeypatch the _Certificate class to add __deepcopy__() so that when we call asdict() on a dataclass
    # that contains a _Certificate, asdict() succeeds. Without this, generating JSON for the certinfo scan command
    # will crash because the asdict() function uses deepcopy(), but certificates returned by cryptography.x509
    # don't support it so SSLyze would crash. This class is a workaround to fix JSON output.
    # I opened an issue about it in the cryptography repo at https://github.com/pyca/cryptography/issues/5129
    def _deepcopy_method_for_x509_certificate(inner_self: _Certificate, memo: str) -> x509.Certificate:
        return x509.load_pem_x509_certificate(inner_self.public_bytes(Encoding.PEM), backend=default_backend())

    _Certificate.__deepcopy__ = _deepcopy_method_for_x509_certificate

    # Same problem with OCSPResponse objects
    def _deepcopy_method_for_ocsp_response(inner_self: _OCSPResponse, memo: str) -> _OCSPResponse:
        return load_der_ocsp_response(inner_self.public_bytes(Encoding.DER))

    _OCSPResponse.__deepcopy__ = _deepcopy_method_for_ocsp_response


# Call it on import... hacky but we don't have a choice
_monkeypatch_to_fix_certificate_asdict()


@dataclass(frozen=True)
class _ObjectIdentifierAsJson:
    name: str
    dotted_string: str


def oid_to_json(obj: ObjectIdentifier) -> Dict[str, str]:
    return asdict(_ObjectIdentifierAsJson(name=obj._name, dotted_string=obj.dotted_string))


# We use dataclasses here to ensure consistency in how we serialize X509 names
@dataclass(frozen=True)
class _X509NameAttributeAsJson:
    oid: ObjectIdentifier  # To be serialized by _oid_to_json()
    value: str
    rfc4514_string: str


@dataclass(frozen=True)
class _X509NameAsJson:
    rfc4514_string: str
    attributes: List[_X509NameAttributeAsJson]


def x509_name_to_json(name: x509.Name) -> Dict[str, Any]:
    attributes = []
    for attr in name:
        attributes.append(
            _X509NameAttributeAsJson(oid=attr.oid, value=attr.value, rfc4514_string=attr.rfc4514_string())
        )

    x509name_as_json = _X509NameAsJson(rfc4514_string=name.rfc4514_string(), attributes=attributes)
    return asdict(x509name_as_json)


@dataclass(frozen=True)
class _PublicKeyAsJson:
    algorithm: str
    key_size: Optional[int]  # None for Ed25519PublicKey and Ed448PublicKey

    # Only set if the algorithm is RSA
    rsa_e: Optional[int]
    rsa_n: Optional[int]

    # Only set if the algorithm is Elliptic Curve
    ec_curve_name: Optional[str]
    ec_x: Optional[int]
    ec_y: Optional[int]


@dataclass(frozen=True)
class _SubjAltNameAsJson:
    dns: List[str]


@dataclass(frozen=True)
class _HashAlgorithmAsJson:
    name: str
    digest_size: int


@dataclass(frozen=True)
class _X509CertificateAsJson:
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
    signature_algorithm_oid: ObjectIdentifier

    # We may get garbage/invalid certificates that do not have a subject or an issuer, hence they can be None
    # https://github.com/nabla-c0d3/sslyze/issues/403
    subject: Optional[x509.name.Name]
    issuer: Optional[x509.name.Name]

    public_key: _PublicKeyAsJson


def x509_certificate_to_json(certificate: x509.Certificate) -> Dict[str, Any]:
    public_key = certificate.public_key()

    try:
        public_key_size = public_key.key_size  # type: ignore
    except AttributeError:
        public_key_size = None

    public_key_json = _PublicKeyAsJson(
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

    signature_hash_algorithm: Optional[_HashAlgorithmAsJson]
    if certificate.signature_hash_algorithm:
        signature_hash_algorithm = _HashAlgorithmAsJson(
            name=certificate.signature_hash_algorithm.name,
            digest_size=certificate.signature_hash_algorithm.digest_size,
        )
    else:
        signature_hash_algorithm = None

    # We may get garbage/invalid certificates so we need to handle ValueErrors.
    # See https://github.com/nabla-c0d3/sslyze/issues/403 for more information
    subject_field: Optional[x509.name.Name]
    try:
        subject_field = certificate.subject
    except ValueError:
        subject_field = None

    issuer_field: Optional[x509.name.Name]
    try:
        issuer_field = certificate.issuer
    except ValueError:
        issuer_field = None

    cert_as_json = _X509CertificateAsJson(
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
        public_key=public_key_json,
    )
    return asdict(cert_as_json)


@dataclass(frozen=True)
class _OcspResponseAsJson:
    response_status: str

    certificate_status: Optional[str]
    revocation_time: Optional[datetime]

    produced_at: Optional[datetime]
    this_update: Optional[datetime]
    next_update: Optional[datetime]

    serial_number: Optional[str]


def ocsp_response_to_json(ocsp_response: x509.ocsp.OCSPResponse) -> Dict[str, Any]:
    response_status = ocsp_response.response_status.name
    if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
        return asdict(
            _OcspResponseAsJson(
                response_status=response_status,
                certificate_status=None,
                revocation_time=None,
                produced_at=None,
                this_update=None,
                next_update=None,
                serial_number=None,
            )
        )
    else:
        return asdict(
            _OcspResponseAsJson(
                response_status=response_status,
                certificate_status=ocsp_response.certificate_status.name,
                revocation_time=ocsp_response.revocation_time,
                produced_at=ocsp_response.produced_at,
                this_update=ocsp_response.this_update,
                next_update=ocsp_response.next_update,
                serial_number=ocsp_response.serial_number,
            )
        )
