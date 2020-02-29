"""JSON serialization logic for objects only returned by the certificate info plugin.
"""
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.backends.openssl import x509

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import Encoding

from sslyze.cli import json_output
from sslyze.plugins.certificate_info.certificate_utils import CertificateUtils


@json_output.object_to_json.register
def _oid(obj: ObjectIdentifier) -> json_output.JsonType:
    return obj.dotted_string


@json_output.object_to_json.register
def _cert(obj: x509._Certificate) -> json_output.JsonType:
    certificate = obj
    result = {
        # Add general info
        "as_pem": obj.public_bytes(Encoding.PEM).decode("ascii"),
        "hpkp_pin": CertificateUtils.get_hpkp_pin(obj),
        # Add some of the fields of the cert
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serialNumber": str(certificate.serial_number),
        "notBefore": certificate.not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
        "notAfter": certificate.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
        "signatureAlgorithm": certificate.signature_hash_algorithm.name,
        "publicKey": {"algorithm": CertificateUtils.get_public_key_type(certificate)},
    }

    dns_alt_names = CertificateUtils.get_dns_subject_alternative_names(certificate)
    if dns_alt_names:
        result["subjectAlternativeName"] = {"DNS": dns_alt_names}  # type: ignore

    # Add some info about the public key
    public_key = certificate.public_key()
    if isinstance(public_key, EllipticCurvePublicKey):
        result["publicKey"]["size"] = str(public_key.curve.key_size)  # type: ignore
        result["publicKey"]["curve"] = public_key.curve.name  # type: ignore
    else:
        result["publicKey"]["size"] = str(public_key.key_size)
        result["publicKey"]["exponent"] = str(public_key.public_numbers().e)
    return result
