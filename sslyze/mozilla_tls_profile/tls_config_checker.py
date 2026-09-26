import json
from enum import Enum
from pathlib import Path
from typing import Annotated

import pydantic
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from nassl.ephemeral_key_info import DhEphemeralKeyInfo, EcDhEphemeralKeyInfo

from sslyze import (
    AllScanCommandsAttempts,
    CertificateInfoScanResult,
    CipherSuitesScanResult,
    RobotScanResultEnum,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    ServerScanResult,
    ServerScanStatusEnum,
)
from sslyze.plugins.http_headers_plugin import HttpHeadersScanResult
from sslyze.plugins.supported_groups_plugin import SupportedGroupsScanResult


class _MozillaCiphersAsJson(pydantic.BaseModel):
    caddy: set[str]
    go: set[str]
    iana: set[str]
    openssl: set[str]


# ANSI X9.62 name (used by the Mozilla TLS profiles) -> SECG name
# Based on https://www.rfc-editor.org/rfc/rfc8422.html#appendix-A
_MOZILLA_CURVE_NAME_TO_SECG_CURVE_NAME = {
    "prime256v1": "secp256r1",
    "prime192v1": "secp192r1",
}


def _convert_mozilla_curve_name_to_secg_name(mozilla_curves: set[str]) -> set[str]:
    # Some curves use the ANSI X9.62 name in the Mozilla TLS profiles; convert the names to SECG names
    mozilla_curves_secg_names = set()
    for curve_name in mozilla_curves:
        try:
            final_curve_name = _MOZILLA_CURVE_NAME_TO_SECG_CURVE_NAME[curve_name]
        except KeyError:
            final_curve_name = curve_name
        mozilla_curves_secg_names.add(final_curve_name)

    return mozilla_curves_secg_names


class TlsConfigurationAsJson(pydantic.BaseModel):
    certificate_curves: Annotated[set[str], pydantic.AfterValidator(_convert_mozilla_curve_name_to_secg_name)]
    certificate_signatures: set[str]
    certificate_types: set[str]
    ciphersuites: set[str]
    ciphers: _MozillaCiphersAsJson
    dh_param_size: int | None
    ecdh_param_size: int
    hsts_min_age: int
    maximum_certificate_lifespan: int
    ocsp_staple: bool
    recommended_certificate_lifespan: int
    rsa_key_size: int | None
    server_preferred_order: bool
    tls_curves: Annotated[set[str], pydantic.AfterValidator(_convert_mozilla_curve_name_to_secg_name)]
    tls_versions: set[str]


class _AllMozillaTlsConfigurationsAsJson(pydantic.BaseModel):
    modern: TlsConfigurationAsJson
    intermediate: TlsConfigurationAsJson
    old: TlsConfigurationAsJson


class _MozillaTlsProfileAsJson(pydantic.BaseModel):
    version: float
    href: str
    configurations: _AllMozillaTlsConfigurationsAsJson


class TlsConfigurationEnum(str, Enum):
    MOZILLA_MODERN = "modern"
    MOZILLA_INTERMEDIATE = "intermediate"
    MOZILLA_OLD = "old"
    CUSTOM = "custom"


class ServerNotCompliantWithTlsConfiguration(Exception):
    def __init__(
        self,
        tls_configuration: TlsConfigurationAsJson,
        issues: dict[str, str],
    ):
        self.tls_configuration = tls_configuration
        self.issues = issues

    def __str__(self) -> str:
        return f"Server is not compliant with the supplied TLS configuration due to: {self.issues}"


class ServerScanResultIncomplete(Exception):
    """The server scan result does not have enough information to check it against Mozilla's configuration."""


SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER: set[ScanCommand] = {
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.HEARTBLEED,
    ScanCommand.ROBOT,
    ScanCommand.OPENSSL_CCS_INJECTION,
    ScanCommand.TLS_FALLBACK_SCSV,
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.SESSION_RENEGOTIATION,
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.SUPPORTED_GROUPS,
    ScanCommand.TLS_EXTENDED_MASTER_SECRET,
    ScanCommand.SUPPORTED_GROUPS,  # For elliptic curves
    ScanCommand.ENCRYPTED_CLIENT_HELLO,  # Not part of the Mozilla config, but we want to run this by default
    # ScanCommand.HTTP_HEADERS,  # Disabled for now; see below
}


class MozillaTlsConfiguration:
    _JSON_PROFILE_PATH = Path(__file__).parent.absolute() / "5.7.json"

    @classmethod
    def get(cls, tls_configuration_enum: TlsConfigurationEnum) -> TlsConfigurationAsJson:
        json_profile_as_str = cls._JSON_PROFILE_PATH.read_text()
        parsed_profile = _MozillaTlsProfileAsJson(**json.loads(json_profile_as_str))
        tls_config = getattr(parsed_profile.configurations, tls_configuration_enum.value)
        return tls_config


def check_server_against_tls_configuration(
    server_scan_result: ServerScanResult,
    tls_config_to_check_against: TlsConfigurationAsJson,
) -> None:
    # Ensure the scan was successful
    if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
        raise ServerScanResultIncomplete("The server scan was not completed.")

    # Ensure all the scan command we need were run successfully
    for scan_command in SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER:
        scan_cmd_attempt = getattr(server_scan_result.scan_result, scan_command.value)
        if scan_cmd_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            raise ServerScanResultIncomplete(f"The {scan_command.value} result is missing.")

    # Now look for issues
    all_issues: dict[str, str] = {}

    # Checks on the certificate
    assert server_scan_result.scan_result
    assert server_scan_result.scan_result.certificate_info
    assert server_scan_result.scan_result.certificate_info.result
    issues_with_certificates = _check_certificates(
        cert_info_result=server_scan_result.scan_result.certificate_info.result,
        tls_config=tls_config_to_check_against,
    )
    all_issues.update(issues_with_certificates)

    # Checks on the TLS versions and cipher suites
    assert server_scan_result.scan_result
    issues_with_tls_ciphers = _check_tls_versions_and_ciphers(
        server_scan_result.scan_result, tls_config_to_check_against
    )
    all_issues.update(issues_with_tls_ciphers)

    # Checks on the TLS elliptic curves
    assert server_scan_result.scan_result.supported_groups.result
    issues_with_tls_curves = _check_tls_curves(
        server_scan_result.scan_result.supported_groups.result,
        tls_config_to_check_against,
    )
    all_issues.update(issues_with_tls_curves)

    # Checks on TLS vulnerabilities
    issues_with_tls_vulns = _check_tls_vulnerabilities(server_scan_result.scan_result)
    all_issues.update(issues_with_tls_vulns)

    # TODO(AD): Re-enable this check. Right now nobody follows the recommendation of the Mozilla profile
    # to have an HSTS max-age of 63072000 seconds (2 years).
    # Check the HSTS header
    # assert server_scan_result.scan_result.http_headers
    # assert server_scan_result.scan_result.http_headers.result
    # issue_with_hsts = _check_http_headers(server_scan_result.scan_result.http_headers.result, mozilla_config)
    # all_issues.update(issue_with_hsts)

    if all_issues:
        raise ServerNotCompliantWithTlsConfiguration(
            tls_configuration=tls_config_to_check_against,
            issues=all_issues,
        )


def _check_tls_curves(
    supported_groups_result: SupportedGroupsScanResult,
    tls_config: TlsConfigurationAsJson,
) -> dict[str, str]:
    issues_with_tls_curves = {}
    # Starting with the 6.0 config, the tls_curves requirement may contain PQ groups as well (which are not EC groups)
    #  so we also add them here
    supported_curves_and_pq_goups: set[str] = set()
    if supported_groups_result.supported_elliptic_curve_groups:
        supported_curves_and_pq_goups.update([grp for grp in supported_groups_result.supported_elliptic_curve_groups])
    if supported_groups_result.supported_post_quantum_groups:
        supported_curves_and_pq_goups.update([grp for grp in supported_groups_result.supported_post_quantum_groups])

    tls_curves_difference = supported_curves_and_pq_goups - tls_config.tls_curves
    if tls_curves_difference:
        issues_with_tls_curves["tls_curves"] = (
            f"TLS curves {tls_curves_difference} are supported, but should be rejected."
        )

    return issues_with_tls_curves


def _check_tls_vulnerabilities(scan_result: AllScanCommandsAttempts) -> dict[str, str]:
    issues_with_tls_vulns = {}
    assert scan_result.tls_compression.result
    if scan_result.tls_compression.result.supports_compression:
        issues_with_tls_vulns["tls_vulnerability_compression"] = "Server is vulnerable to TLS compression attacks."

    assert scan_result.openssl_ccs_injection.result
    if scan_result.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection:
        issues_with_tls_vulns["tls_vulnerability_ccs_injection"] = (
            "Server is vulnerable to the OpenSSL CCS injection attack."
        )

    assert scan_result.tls_fallback_scsv.result
    if not scan_result.tls_fallback_scsv.result.supports_fallback_scsv:
        issues_with_tls_vulns["tls_vulnerability_fallback_scsv"] = (
            "Server is vulnerable to TLS downgrade attacks because it does not support the TLS_FALLBACK_SCSV mechanism."
        )

    assert scan_result.heartbleed.result
    if scan_result.heartbleed.result.is_vulnerable_to_heartbleed:
        issues_with_tls_vulns["tls_vulnerability_heartbleed"] = "Server is vulnerable to the OpenSSL Heartbleed attack."

    assert scan_result.robot.result
    if scan_result.robot.result.robot_result == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
        issues_with_tls_vulns["tls_vulnerability_robot"] = "Server is vulnerable to the ROBOT attack."

    assert scan_result.session_renegotiation.result
    if not scan_result.session_renegotiation.result.supports_secure_renegotiation:
        issues_with_tls_vulns["tls_vulnerability_renegotiation"] = (
            "Server is vulnerable to the insecure renegotiation attack."
        )

    assert scan_result.tls_extended_master_secret.result
    if not scan_result.tls_extended_master_secret.result.supports_ems_extension:
        issues_with_tls_vulns["tls_vulnerability_extended_master_secret"] = (
            "Server does not support the Extended Master Secret TLS extension."
        )

    return issues_with_tls_vulns


def _check_tls_versions_and_ciphers(
    scan_result: AllScanCommandsAttempts,
    tls_config: TlsConfigurationAsJson,
) -> dict[str, str]:
    # First parse the results related to TLS versions and ciphers
    tls_versions_supported = set()
    cipher_suites_supported = set()
    tls_1_3_cipher_suites_supported = set()
    curves_supported = set()
    smallest_ecdh_param_size = 100000
    smallest_dh_param_size = 100000
    for field_name, tls_version_name in [
        ("ssl_2_0_cipher_suites", "SSLv2"),
        ("ssl_3_0_cipher_suites", "SSLv3"),
        ("tls_1_0_cipher_suites", "TLSv1"),
        ("tls_1_1_cipher_suites", "TLSv1.1"),
        ("tls_1_2_cipher_suites", "TLSv1.2"),
        ("tls_1_3_cipher_suites", "TLSv1.3"),
    ]:
        tls_scan_result: CipherSuitesScanResult = getattr(scan_result, field_name).result
        if tls_scan_result.is_tls_version_supported:
            tls_versions_supported.add(tls_version_name)
            for accepted_cipher_suite in tls_scan_result.accepted_cipher_suites:
                if tls_version_name == "TLSv1.3":
                    tls_1_3_cipher_suites_supported.add(accepted_cipher_suite.cipher_suite.name)
                else:
                    cipher_suites_supported.add(accepted_cipher_suite.cipher_suite.name)

                ephemeral_key = accepted_cipher_suite.ephemeral_key
                if isinstance(ephemeral_key, EcDhEphemeralKeyInfo):
                    curves_supported.add(ephemeral_key.curve_name)
                    actual_key_size = ephemeral_key.size + 3  # OpenSSL returns 253 instead of 255 for the secret key
                    smallest_ecdh_param_size = min([smallest_ecdh_param_size, actual_key_size])

                elif isinstance(ephemeral_key, DhEphemeralKeyInfo):
                    smallest_dh_param_size = min([smallest_dh_param_size, ephemeral_key.size])

    # Then check the results
    issues_with_tls_ciphers = {}
    tls_versions_difference = tls_versions_supported - tls_config.tls_versions
    if tls_versions_difference:
        issues_with_tls_ciphers["tls_versions"] = (
            f"TLS versions {tls_versions_difference} are supported, but should be rejected."
        )

    tls_1_3_cipher_suites_difference = tls_1_3_cipher_suites_supported - tls_config.ciphersuites
    if tls_1_3_cipher_suites_difference:
        issues_with_tls_ciphers["ciphersuites"] = (
            f"TLS 1.3 cipher suites {tls_1_3_cipher_suites_difference} are supported, but should be rejected."
        )

    cipher_suites_difference = cipher_suites_supported - tls_config.ciphers.iana
    if cipher_suites_difference:
        issues_with_tls_ciphers["ciphers"] = (
            f"Cipher suites {cipher_suites_difference} are supported, but should be rejected."
        )

    if tls_config.ecdh_param_size and smallest_ecdh_param_size < tls_config.ecdh_param_size:
        issues_with_tls_ciphers["ecdh_param_size"] = (
            f"ECDH parameter size is {smallest_ecdh_param_size},"
            f" should be superior or equal to {tls_config.ecdh_param_size}."
        )

    if tls_config.dh_param_size and smallest_dh_param_size < tls_config.dh_param_size:
        issues_with_tls_ciphers["dh_param_size"] = (
            f"DH parameter size is {smallest_dh_param_size}, should be superior or equal to {tls_config.dh_param_size}."
        )

    return issues_with_tls_ciphers


def _check_certificates(
    cert_info_result: CertificateInfoScanResult,
    tls_config: TlsConfigurationAsJson,
) -> dict[str, str]:
    issues_with_certificates = {}
    deployed_key_algorithms = set()
    deployed_signature_algorithms = set()
    for cert_deployment in cert_info_result.certificate_deployments:
        # Validate certificate trust
        leaf_cert = cert_deployment.received_certificate_chain[0]
        if not cert_deployment.verified_certificate_chain:
            issues_with_certificates["certificate_path_validation"] = (
                f"Certificate path validation failed for {leaf_cert.subject.rfc4514_string()}."
            )

        # Validate the public key
        public_key = leaf_cert.public_key()
        if isinstance(public_key, EllipticCurvePublicKey):
            deployed_key_algorithms.add("ecdsa")
            if public_key.curve.name not in tls_config.certificate_curves:
                issues_with_certificates["certificate_curves"] = (
                    f"Certificate curve is {public_key.curve.name}, should be one of {tls_config.certificate_curves}."
                )

        elif isinstance(public_key, RSAPublicKey):
            deployed_key_algorithms.add("rsa")
            if tls_config.rsa_key_size and public_key.key_size < tls_config.rsa_key_size:
                issues_with_certificates["rsa_key_size"] = (
                    f"RSA key size is {public_key.key_size}, minimum allowed is {tls_config.rsa_key_size}."
                )

        else:
            deployed_key_algorithms.add(public_key.__class__.__name__)

        deployed_signature_algorithms.add(leaf_cert.signature_algorithm_oid._name)  # type: ignore

        # Validate the cert's lifespan
        leaf_cert_lifespan = leaf_cert.not_valid_after_utc - leaf_cert.not_valid_before_utc
        if leaf_cert_lifespan.days > tls_config.maximum_certificate_lifespan:
            issues_with_certificates["maximum_certificate_lifespan"] = (
                f"Certificate life span is {leaf_cert_lifespan.days} days,"
                f" should be less than {tls_config.maximum_certificate_lifespan}."
            )

    # TODO(AD): It's unclear whether the Mozilla profile/configs takes into accounts servers with multiple leaf certs
    #  What follows is my personal guess as to how it should work for multi-certs deployments...

    # Validate the public key algorithms
    # At least one of the Mozilla cert types should have been detected in the server's cert deployments
    found_cert_type = False
    for key_algorithm in tls_config.certificate_types:
        if key_algorithm in deployed_key_algorithms:
            found_cert_type = True
            break
    if not found_cert_type:
        issues_with_certificates["certificate_types"] = (
            f"Deployed certificate types are {deployed_key_algorithms},"
            f" should have at least one of {tls_config.certificate_types}."
        )

    # Validate the signature algorithms
    found_sig_algorithm = False
    for sig_algorithm in tls_config.certificate_signatures:
        if sig_algorithm in deployed_signature_algorithms:
            found_sig_algorithm = True
            break
    if not found_sig_algorithm:
        issues_with_certificates["certificate_signatures"] = (
            f"Deployed certificate signatures are {deployed_signature_algorithms},"
            f" should have at least one of {tls_config.certificate_signatures}."
        )

    # TODO(AD): Maybe add check for ocsp_staple but that one seems optional in https://ssl-config.mozilla.org/

    return issues_with_certificates


def _check_http_headers(
    http_headers_result: HttpHeadersScanResult,
    tls_config: TlsConfigurationAsJson,
) -> dict[str, str]:
    issues_with_http_headers = {}

    if not http_headers_result.strict_transport_security_header:
        issues_with_http_headers["hsts_min_age"] = "HSTS header is missing."

    elif not http_headers_result.strict_transport_security_header.max_age:
        issues_with_http_headers["hsts_min_age"] = "HSTS max-age directive is missing."

    else:
        if http_headers_result.strict_transport_security_header.max_age < tls_config.hsts_min_age:
            issues_with_http_headers["hsts_min_age"] = (
                f"HSTS max-age is {http_headers_result.strict_transport_security_header.max_age},"
                f" should be superior or equal to {tls_config.hsts_min_age}."
            )

    return issues_with_http_headers
