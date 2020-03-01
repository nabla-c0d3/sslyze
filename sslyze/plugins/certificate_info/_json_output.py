"""JSON serialization logic for objects only returned by the certificate info plugin.
"""
from base64 import b64encode
from typing import Dict, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.x509 import _Certificate
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from sslyze.plugins.certificate_info._certificate_utils import (
    get_public_key_sha256,
    extract_dns_subject_alternative_names,
)


def register_json_serializer_functions() -> None:
    # Avoid circular imports
    from sslyze.cli.json_output import object_to_json

    # Register special deserialization functions
    object_to_json.register(_oid_to_json)
    object_to_json.register(_certificate_to_json)

    # H4ck: monkeypatch the _Certificate class to add __deepcopy__() so that when we call asdict() on a dataclass
    # that contains a _Certificate, asdict() succeeds. Without this, generating JSON for the certinfo scan command
    # will crash because the asdict() function uses deepcopy(), but certificates returned by cryptography.x509
    # don't support it so SSLyze would crash. This class is a workaround to fix JSON output.
    def _deepcopy_method_for_x509_certificate(inner_self: _Certificate, memo: str) -> x509.Certificate:
        return x509.load_pem_x509_certificate(inner_self.public_bytes(Encoding.PEM), backend=default_backend())

    _Certificate.__deepcopy__ = _deepcopy_method_for_x509_certificate


def _oid_to_json(obj: ObjectIdentifier) -> str:
    return obj.dotted_string


def _certificate_to_json(certificate: x509.Certificate) -> Dict[str, Any]:
    result = {
        # Add general info
        "as_pem": certificate.public_bytes(Encoding.PEM).decode("ascii"),
        "hpkp_pin": b64encode(get_public_key_sha256(certificate)).decode("utf-8"),  # RFC 7469
        # Add some of the fields of the cert
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serialNumber": str(certificate.serial_number),
        "notBefore": certificate.not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
        "notAfter": certificate.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
        "signatureAlgorithm": certificate.signature_hash_algorithm.name,
        "subjectAlternativeName": {"DNS": extract_dns_subject_alternative_names(certificate)},
    }

    # Add some info about the public key
    public_key = certificate.public_key()
    public_key_dict = {"algorithm": public_key.__class__.__name__}
    if isinstance(public_key, EllipticCurvePublicKey):
        public_key_dict["size"] = str(public_key.curve.key_size)
        public_key_dict["curve"] = public_key.curve.name
    else:
        public_key_dict["size"] = str(public_key.key_size)
        public_key_dict["exponent"] = str(public_key.public_numbers().e)
    result["publicKey"] = public_key_dict
    return result
