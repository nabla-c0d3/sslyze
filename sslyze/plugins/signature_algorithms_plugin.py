from dataclasses import dataclass
from enum import Enum

from nassl.base_ssl_client import ClientCertificateRequested
from nassl.ephemeral_key_info import OpenSslEvpPkeyEnum
from nassl.errors import OpenSSLError
from nassl.openssl_1_1_1.ssl_client import OpenSslDigestNidEnum, SslClient_OpenSSL_1_1_1

from sslyze.connection_helpers.tls_connection import OpenSslVersionEnum
from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandCliConnector,
    ScanCommandExtraArgument,
    ScanCommandImplementation,
    ScanCommandResult,
    ScanCommandWrongUsageError,
    ScanJob,
    ScanJobResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum, enable_ecdh_cipher_suites


class SignatureAlgorithm(str, Enum):
    """A signature algorithm that a client can offer in the TLS signature_algorithms extension.

    The names follow the TLS 1.3 SignatureScheme registry (RFC 8446) where they map cleanly; the
    generic ecdsa_* names are used because SSL_set1_sigalgs() only lets us pin the digest and the key
    type, not the curve.
    """

    RSA_PKCS1_SHA1 = "rsa_pkcs1_sha1"
    RSA_PKCS1_SHA224 = "rsa_pkcs1_sha224"
    RSA_PKCS1_SHA256 = "rsa_pkcs1_sha256"
    RSA_PKCS1_SHA384 = "rsa_pkcs1_sha384"
    RSA_PKCS1_SHA512 = "rsa_pkcs1_sha512"
    ECDSA_SHA1 = "ecdsa_sha1"
    ECDSA_SHA224 = "ecdsa_sha224"
    ECDSA_SHA256 = "ecdsa_sha256"
    ECDSA_SHA384 = "ecdsa_sha384"
    ECDSA_SHA512 = "ecdsa_sha512"
    RSA_PSS_RSAE_SHA256 = "rsa_pss_rsae_sha256"
    RSA_PSS_RSAE_SHA384 = "rsa_pss_rsae_sha384"
    RSA_PSS_RSAE_SHA512 = "rsa_pss_rsae_sha512"


# Each signature algorithm maps to the (digest, public key) NID pair that SSL_set1_sigalgs() expects
_SIGNATURE_ALGORITHM_TO_NASSL: dict[SignatureAlgorithm, tuple[OpenSslDigestNidEnum, OpenSslEvpPkeyEnum]] = {
    SignatureAlgorithm.RSA_PKCS1_SHA1: (OpenSslDigestNidEnum.SHA1, OpenSslEvpPkeyEnum.RSA),
    SignatureAlgorithm.RSA_PKCS1_SHA224: (OpenSslDigestNidEnum.SHA224, OpenSslEvpPkeyEnum.RSA),
    SignatureAlgorithm.RSA_PKCS1_SHA256: (OpenSslDigestNidEnum.SHA256, OpenSslEvpPkeyEnum.RSA),
    SignatureAlgorithm.RSA_PKCS1_SHA384: (OpenSslDigestNidEnum.SHA384, OpenSslEvpPkeyEnum.RSA),
    SignatureAlgorithm.RSA_PKCS1_SHA512: (OpenSslDigestNidEnum.SHA512, OpenSslEvpPkeyEnum.RSA),
    SignatureAlgorithm.ECDSA_SHA1: (OpenSslDigestNidEnum.SHA1, OpenSslEvpPkeyEnum.EC),
    SignatureAlgorithm.ECDSA_SHA224: (OpenSslDigestNidEnum.SHA224, OpenSslEvpPkeyEnum.EC),
    SignatureAlgorithm.ECDSA_SHA256: (OpenSslDigestNidEnum.SHA256, OpenSslEvpPkeyEnum.EC),
    SignatureAlgorithm.ECDSA_SHA384: (OpenSslDigestNidEnum.SHA384, OpenSslEvpPkeyEnum.EC),
    SignatureAlgorithm.ECDSA_SHA512: (OpenSslDigestNidEnum.SHA512, OpenSslEvpPkeyEnum.EC),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA256: (OpenSslDigestNidEnum.SHA256, OpenSslEvpPkeyEnum.RSA_PSS),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA384: (OpenSslDigestNidEnum.SHA384, OpenSslEvpPkeyEnum.RSA_PSS),
    SignatureAlgorithm.RSA_PSS_RSAE_SHA512: (OpenSslDigestNidEnum.SHA512, OpenSslEvpPkeyEnum.RSA_PSS),
}


@dataclass(frozen=True)
class SignatureAlgorithmsScanResult(ScanCommandResult):
    """The result of testing which signature algorithms a server accepts for the TLS handshake signature.

    Attributes:
        supported_signature_algorithms: The list of signature algorithms the server completed a handshake with.
        rejected_signature_algorithms: The list of signature algorithms the server would not use.
    """

    supported_signature_algorithms: list[SignatureAlgorithm]
    rejected_signature_algorithms: list[SignatureAlgorithm]

    def __post_init__(self) -> None:
        # Sort the algorithms by name
        if self.supported_signature_algorithms:
            self.supported_signature_algorithms.sort(key=lambda sig_alg: sig_alg.value)
        if self.rejected_signature_algorithms:
            self.rejected_signature_algorithms.sort(key=lambda sig_alg: sig_alg.value)


class SignatureAlgorithmsScanResultAsJson(BaseModelWithOrmModeAndForbid):
    supported_signature_algorithms: list[str]
    rejected_signature_algorithms: list[str]


assert SignatureAlgorithmsScanResult.__doc__
SignatureAlgorithmsScanResultAsJson.__doc__ = SignatureAlgorithmsScanResult.__doc__


class SignatureAlgorithmsScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: SignatureAlgorithmsScanResultAsJson | None


class _SignatureAlgorithmsCliConnector(ScanCommandCliConnector[SignatureAlgorithmsScanResult, None]):
    _cli_option = "signature_algorithms"
    _cli_description = "Test a server for the signature algorithms it accepts for the TLS handshake."

    @classmethod
    def result_to_console_output(cls, result: SignatureAlgorithmsScanResult) -> list[str]:
        result_as_txt = [cls._format_title("Signature Algorithms")]

        supported = [sig_alg.value for sig_alg in result.supported_signature_algorithms]
        rejected = [sig_alg.value for sig_alg in result.rejected_signature_algorithms]
        if supported:
            result_as_txt.append(cls._format_field("Supported signature algorithms:", ", ".join(supported)))
        else:
            result_as_txt.append(
                cls._format_subtitle("The server did not accept any of the tested signature algorithms.")
            )
        result_as_txt.append(cls._format_field("Rejected signature algorithms:", ", ".join(rejected)))
        return result_as_txt


class SignatureAlgorithmsImplementation(ScanCommandImplementation[SignatureAlgorithmsScanResult, None]):
    """Test a server for the signature algorithms it accepts for the TLS handshake."""

    cli_connector_cls = _SignatureAlgorithmsCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: ScanCommandExtraArgument | None = None
    ) -> list[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [
            ScanJob(function_to_call=_test_signature_algorithm, function_arguments=[server_info, sig_alg])
            for sig_alg in SignatureAlgorithm
        ]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: list[ScanJobResult]
    ) -> SignatureAlgorithmsScanResult:
        if len(scan_job_results) != len(SignatureAlgorithm):
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        all_results = [scan_job.get_result() for scan_job in scan_job_results]
        return SignatureAlgorithmsScanResult(
            supported_signature_algorithms=[r.signature_algorithm for r in all_results if r.was_accepted_by_server],
            rejected_signature_algorithms=[r.signature_algorithm for r in all_results if not r.was_accepted_by_server],
        )


@dataclass(frozen=True)
class _SignatureAlgorithmResult:
    signature_algorithm: SignatureAlgorithm
    was_accepted_by_server: bool


def _test_signature_algorithm(
    server_info: ServerConnectivityInfo, signature_algorithm: SignatureAlgorithm
) -> _SignatureAlgorithmResult:
    tls_version = server_info.tls_probing_result.highest_tls_version_supported
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, openssl_version=OpenSslVersionEnum.OPENSSL_1_1_1
    )
    assert isinstance(ssl_connection.ssl_client, SslClient_OpenSSL_1_1_1), "Should never happen"

    # A signature only shows up in the handshake if the key exchange is signed (TLS 1.3 always signs the
    # CertificateVerify; for TLS 1.2 we force an (EC)DHE cipher suite so the server signs the key exchange).
    if tls_version != TlsVersionEnum.TLS_1_3:
        enable_ecdh_cipher_suites(tls_version, ssl_connection.ssl_client)

    digest_nid, public_key_nid = _SIGNATURE_ALGORITHM_TO_NASSL[signature_algorithm]
    ssl_connection.ssl_client.set_signature_algorithms([(digest_nid, public_key_nid)])

    was_accepted_by_server = False
    try:
        ssl_connection.connect()
        was_accepted_by_server = True

    except ClientCertificateRequested:
        # The server got far enough to ask for a client cert, so it accepted the signature algorithm
        was_accepted_by_server = True

    except (ServerRejectedTlsHandshake, TlsHandshakeTimedOut):
        was_accepted_by_server = False

    except OpenSSLError as e:
        error_message = e.args[0]
        # The client-side OpenSSL refuses to build a ClientHello when the single offered signature algorithm
        # is not usable for the negotiated TLS version (for example an rsa_pkcs1 or SHA1 algorithm with TLS 1.3);
        # some servers also just send a handshake_failure alert. Either way the algorithm is not usable here.
        if (
            "signature algorithm" in error_message
            or "sigalg" in error_message
            or "sig_alg" in error_message
            or "no shared cipher" in error_message
            or "sslv3 alert handshake failure" in error_message
        ):
            was_accepted_by_server = False
        else:
            raise

    finally:
        ssl_connection.close()

    return _SignatureAlgorithmResult(
        signature_algorithm=signature_algorithm,
        was_accepted_by_server=was_accepted_by_server,
    )
