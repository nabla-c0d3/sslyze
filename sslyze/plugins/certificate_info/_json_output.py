"""JSON serialization logic for objects only returned by the certificate info plugin.
"""
from base64 import b64encode
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.x509 import _Certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
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


# Call it on import... hacky but we don't have a choice
_monkeypatch_to_fix_certificate_asdict()


def oid_to_json(obj: ObjectIdentifier) -> Dict[str, str]:
    return {"name": obj._name, "dotted_string": obj.dotted_string}


# We use dataclasses here to ensure consistency in how we serialize X509 names
@dataclass(frozen=True)
class _X509NameAttributeAsJson:
    oid: ObjectIdentifier  # To be serialized by _oid_to_json()
    value: str
    rfc4514_string: str


@dataclass(frozen=True)
class _X509NameAsJson:
    rfc4514_string: Optional[str]  # None if parsing_error is set
    attributes: Optional[List[_X509NameAttributeAsJson]]  # None if parsing_error is set
    parsing_error: Optional[str]


def x509_name_to_json(name: x509.Name) -> Dict[str, Any]:
    attributes = []
    for attr in name:
        attributes.append(
            _X509NameAttributeAsJson(oid=attr.oid, value=attr.value, rfc4514_string=attr.rfc4514_string())
        )

    x509name_as_json = _X509NameAsJson(rfc4514_string=name.rfc4514_string(), attributes=attributes, parsing_error=None)
    return asdict(x509name_as_json)


def x509_certificate_to_json(certificate: x509.Certificate) -> Dict[str, Any]:
    result: Dict[str, Union[None, str, Dict[str, Any]]] = {
        # Add general info
        "as_pem": certificate.public_bytes(Encoding.PEM).decode("ascii"),
        "hpkp_pin": b64encode(get_public_key_sha256(certificate)).decode("utf-8"),  # RFC 7469
        # Add some of the fields of the cert
        "serialNumber": str(certificate.serial_number),
        "notBefore": certificate.not_valid_before.isoformat(),
        "notAfter": certificate.not_valid_after.isoformat(),
        "subjectAlternativeName": {"DNS": extract_dns_subject_alternative_names(certificate)},
    }

    if certificate.signature_hash_algorithm:
        # The signature_hash_algorithm can be None if signature did not use separate hash (ED25519, ED448)
        # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.signature_hash_algorithm
        result["signatureAlgorithm"] = certificate.signature_hash_algorithm.name
    else:
        result["signatureAlgorithm"] = None

    # We may get garbage/invalid certificates so we need to handle ValueErrors.
    # See https://github.com/nabla-c0d3/sslyze/issues/403 for more information
    for name_field in ["subject", "issuer"]:
        try:
            result[name_field] = getattr(certificate, name_field)
        except ValueError as e:
            x509name_as_json = _X509NameAsJson(rfc4514_string=None, attributes=None, parsing_error=e.args[0])
            result[name_field] = asdict(x509name_as_json)

    # Add some info about the public key
    public_key = certificate.public_key()
    public_key_dict: Dict[str, Union[str, int]] = {"algorithm": public_key.__class__.__name__}
    if isinstance(public_key, EllipticCurvePublicKey):
        public_key_dict["size"] = public_key.curve.key_size
        public_key_dict["curve"] = public_key.curve.name
    elif isinstance(public_key, RSAPublicKey):
        public_key_dict["size"] = public_key.key_size
        public_key_dict["exponent"] = public_key.public_numbers().e
    else:
        # DSA Key? https://github.com/nabla-c0d3/sslyze/issues/402
        pass

    result["publicKey"] = public_key_dict
    return result
