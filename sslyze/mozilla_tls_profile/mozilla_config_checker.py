import json
from enum import Enum
from pathlib import Path
from typing import Optional, Set, Dict

import pydantic
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, DhEphemeralKeyInfo

from sslyze import (
    ServerScanResult,
    ServerScanStatusEnum,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    CertificateInfoScanResult,
    AllScanCommandsAttempts,
    CipherSuitesScanResult,
    RobotScanResultEnum,
    SupportedEllipticCurvesScanResult,
)


class _MozillaCiphersAsJson(pydantic.BaseModel):
    caddy: Set[str]
    go: Set[str]
    iana: Set[str]
    openssl: Set[str]


class _MozillaTlsConfigurationAsJson(pydantic.BaseModel):
    certificate_curves: Set[str]
    certificate_signatures: Set[str]
    certificate_types: Set[str]
    ciphersuites: Set[str]
    ciphers: _MozillaCiphersAsJson
    dh_param_size: Optional[int]
    ecdh_param_size: int
    hsts_min_age: int
    maximum_certificate_lifespan: int
    ocsp_staple: bool
    recommended_certificate_lifespan: int
    rsa_key_size: Optional[int]
    server_preferred_order: bool
    tls_curves: Set[str]
    tls_versions: Set[str]


class _AllMozillaTlsConfigurationsAsJson(pydantic.BaseModel):
    modern: _MozillaTlsConfigurationAsJson
    intermediate: _MozillaTlsConfigurationAsJson
    old: _MozillaTlsConfigurationAsJson


class _MozillaTlsProfileAsJson(pydantic.BaseModel):
    version: str
    href: str
    configurations: _AllMozillaTlsConfigurationsAsJson


class MozillaTlsConfigurationEnum(str, Enum):
    MODERN = "modern"
    INTERMEDIATE = "intermediate"
    OLD = "old"


class ServerNotCompliantWithMozillaTlsConfiguration(Exception):
    def __init__(
        self,
        mozilla_config: MozillaTlsConfigurationEnum,
        issues: Dict[str, str],
    ):
        self.mozilla_config = mozilla_config
        self.issues = issues


class ServerScanResultIncomplete(Exception):
    """The server scan result does not have enough information to check it against Mozilla's configuration."""


SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER: Set[ScanCommand] = {
    ScanCommand.SSL_2_0_CIPHER_SUITES,
    ScanCommand.SSL_3_0_CIPHER_SUITES,
    ScanCommand.TLS_1_0_CIPHER_SUITES,
    ScanCommand.TLS_1_1_CIPHER_SUITES,
    ScanCommand.TLS_1_2_CIPHER_SUITES,
    ScanCommand.TLS_1_3_CIPHER_SUITES,
    ScanCommand.HEARTBLEED,
    ScanCommand.ROBOT,
    ScanCommand.OPENSSL_CCS_INJECTION,
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.SESSION_RENEGOTIATION,
    ScanCommand.CERTIFICATE_INFO,
    ScanCommand.ELLIPTIC_CURVES,
}


class MozillaTlsConfigurationChecker:
    def __init__(self, mozilla_tls_profile: _MozillaTlsProfileAsJson):
        self._mozilla_tls_profile = mozilla_tls_profile

    @classmethod
    def get_default(cls) -> "MozillaTlsConfigurationChecker":
        json_profile_path = Path(__file__).parent.absolute() / "5.6.json"
        json_profile_as_str = json_profile_path.read_text()
        parsed_profile = _MozillaTlsProfileAsJson(**json.loads(json_profile_as_str))
        return cls(parsed_profile)

    def check_server(
        self,
        against_config: MozillaTlsConfigurationEnum,
        server_scan_result: ServerScanResult,
    ) -> None:
        # Ensure the scan was successful
        if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
            raise ServerScanResultIncomplete("The server scan was not completed.")

        # Ensure all the scan command we need were run successfully
        for scan_command in SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER:
            scan_cmd_attempt = getattr(server_scan_result.scan_result, scan_command.value)
            if scan_cmd_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
                raise ServerScanResultIncomplete(f"The {scan_command.value} result is missing.")

        # Now let's check the server's scan results against the Mozilla config
        mozilla_config: _MozillaTlsConfigurationAsJson = getattr(
            self._mozilla_tls_profile.configurations, against_config.value
        )
        all_issues: Dict[str, str] = {}

        # Checks on the certificate
        assert server_scan_result.scan_result
        assert server_scan_result.scan_result.certificate_info
        assert server_scan_result.scan_result.certificate_info.result
        issues_with_certificates = _check_certificates(
            cert_info_result=server_scan_result.scan_result.certificate_info.result,
            mozilla_config=mozilla_config,
        )
        all_issues.update(issues_with_certificates)

        # Checks on the TLS versions and cipher suites
        assert server_scan_result.scan_result
        issues_with_tls_ciphers = _check_tls_versions_and_ciphers(server_scan_result.scan_result, mozilla_config)
        all_issues.update(issues_with_tls_ciphers)

        # Checks on the TLS curves
        assert server_scan_result.scan_result.elliptic_curves.result
        issues_with_tls_curves = _check_tls_curves(
            server_scan_result.scan_result.elliptic_curves.result,
            mozilla_config,
        )
        all_issues.update(issues_with_tls_curves)

        # Checks on TLS vulnerabilities
        issues_with_tls_vulns = _check_tls_vulnerabilities(server_scan_result.scan_result)
        all_issues.update(issues_with_tls_vulns)

        if all_issues:
            raise ServerNotCompliantWithMozillaTlsConfiguration(
                mozilla_config=against_config,
                issues=all_issues,
            )


def _check_tls_curves(
    tls_curves_result: SupportedEllipticCurvesScanResult,
    mozilla_config: _MozillaTlsConfigurationAsJson,
) -> Dict[str, str]:
    issues_with_tls_curves = {}
    if tls_curves_result.supported_curves:
        supported_curves = {curve.name for curve in tls_curves_result.supported_curves}
    else:
        supported_curves = set()

    tls_curves_difference = supported_curves - mozilla_config.tls_curves
    if tls_curves_difference:
        issues_with_tls_curves[
            "tls_curves"
        ] = f"TLS curves {tls_curves_difference} are supported, but should be rejected."

    # TODO(AD): Disable the check on the curves; not even Google, Mozilla nor Cloudflare are compliant...
    # return problems_with_tls_curves
    return {}


def _check_tls_vulnerabilities(scan_result: AllScanCommandsAttempts) -> Dict[str, str]:
    issues_with_tls_vulns = {}
    assert scan_result.tls_compression.result
    if scan_result.tls_compression.result.supports_compression:
        issues_with_tls_vulns["tls_vulnerability_compression"] = "Server is vulnerable to TLS compression attacks."

    assert scan_result.openssl_ccs_injection.result
    if scan_result.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection:
        issues_with_tls_vulns[
            "tls_vulnerability_ccs_injection"
        ] = "Server is vulnerable to the OpenSSL CCS injection attack."

    assert scan_result.heartbleed.result
    if scan_result.heartbleed.result.is_vulnerable_to_heartbleed:
        issues_with_tls_vulns["tls_vulnerability_heartbleed"] = "Server is vulnerable to the OpenSSL Heartbleed attack."

    assert scan_result.robot.result
    if scan_result.robot.result.robot_result == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
        issues_with_tls_vulns["tls_vulnerability_robot"] = "Server is vulnerable to the ROBOT attack."

    assert scan_result.session_renegotiation.result
    if not scan_result.session_renegotiation.result.supports_secure_renegotiation:
        issues_with_tls_vulns[
            "tls_vulnerability_renegotiation"
        ] = "Server is vulnerable to the insecure renegotiation attack."

    return issues_with_tls_vulns


def _check_tls_versions_and_ciphers(
    scan_result: AllScanCommandsAttempts,
    mozilla_config: _MozillaTlsConfigurationAsJson,
) -> Dict[str, str]:
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
    tls_versions_difference = tls_versions_supported - mozilla_config.tls_versions
    if tls_versions_difference:
        issues_with_tls_ciphers[
            "tls_versions"
        ] = f"TLS versions {tls_versions_difference} are supported, but should be rejected."

    tls_1_3_cipher_suites_difference = tls_1_3_cipher_suites_supported - mozilla_config.ciphersuites
    if tls_1_3_cipher_suites_difference:
        issues_with_tls_ciphers[
            "ciphersuites"
        ] = f"TLS 1.3 cipher suites {tls_1_3_cipher_suites_difference} are supported, but should be rejected."

    cipher_suites_difference = cipher_suites_supported - mozilla_config.ciphers.iana
    if cipher_suites_difference:
        issues_with_tls_ciphers[
            "ciphers"
        ] = f"Cipher suites {cipher_suites_difference} are supported, but should be rejected."

    if mozilla_config.ecdh_param_size and smallest_ecdh_param_size < mozilla_config.ecdh_param_size:
        issues_with_tls_ciphers["ecdh_param_size"] = (
            f"ECDH parameter size is {smallest_ecdh_param_size},"
            f" should be superior or equal to {mozilla_config.ecdh_param_size}."
        )

    if mozilla_config.dh_param_size and smallest_dh_param_size < mozilla_config.dh_param_size:
        issues_with_tls_ciphers["dh_param_size"] = (
            f"DH parameter size is {smallest_dh_param_size},"
            f" should be superior or equal to {mozilla_config.dh_param_size}."
        )

    return issues_with_tls_ciphers


def _check_certificates(
    cert_info_result: CertificateInfoScanResult,
    mozilla_config: _MozillaTlsConfigurationAsJson,
) -> Dict[str, str]:
    issues_with_certificates = {}
    deployed_key_algorithms = set()
    deployed_signature_algorithms = set()
    for cert_deployment in cert_info_result.certificate_deployments:
        # Validate certificate trust
        leaf_cert = cert_deployment.received_certificate_chain[0]
        if not cert_deployment.leaf_certificate_subject_matches_hostname:
            issues_with_certificates[
                "certificate_hostname_validation"
            ] = f"Certificate hostname validation failed for {leaf_cert.subject.rfc4514_string()}."
        if not cert_deployment.verified_certificate_chain:
            issues_with_certificates[
                "certificate_path_validation"
            ] = f"Certificate path validation failed for {leaf_cert.subject.rfc4514_string()}."

        # Validate the public key
        public_key = leaf_cert.public_key()
        if isinstance(public_key, EllipticCurvePublicKey):
            deployed_key_algorithms.add("ecdsa")
            if public_key.curve.name not in mozilla_config.certificate_curves:
                # TODO(AD): Disable the check on the curves; not even Google and Cloudflare are compliant...
                pass
                # problems_with_certificates["certificate_curves"] = (
                #     f"Certificate curve is {public_key.curve.name},"
                #     f" should be one of {expected_mozilla_config.certificate_curves}."
                # )

        elif isinstance(public_key, RSAPublicKey):
            deployed_key_algorithms.add("rsa")
            if mozilla_config.rsa_key_size and public_key.key_size < mozilla_config.rsa_key_size:
                issues_with_certificates[
                    "rsa_key_size"
                ] = f"RSA key size is {public_key.key_size}, minimum allowed is {mozilla_config.rsa_key_size}."

        else:
            deployed_key_algorithms.add(public_key.__class__.__name__)

        deployed_signature_algorithms.add(leaf_cert.signature_algorithm_oid._name)

        # Validate the cert's lifespan
        leaf_cert_lifespan = leaf_cert.not_valid_after - leaf_cert.not_valid_before
        if leaf_cert_lifespan.days > mozilla_config.maximum_certificate_lifespan:
            issues_with_certificates["maximum_certificate_lifespan"] = (
                f"Certificate life span is {leaf_cert_lifespan.days} days,"
                f" should be less than {mozilla_config.maximum_certificate_lifespan}."
            )

    # TODO(AD): It's unclear whether the Mozilla profile/configs takes into accounts servers with multiple leaf certs
    #  What follows is my personal guess as to how it should work for multi-certs deployments...

    # Validate the public key algorithms
    # At least one of the Mozilla cert types should have been detected in the server's cert deployments
    found_cert_type = False
    for key_algorithm in mozilla_config.certificate_types:
        if key_algorithm in deployed_key_algorithms:
            found_cert_type = True
            break
    if not found_cert_type:
        issues_with_certificates["certificate_types"] = (
            f"Deployed certificate types are {deployed_key_algorithms},"
            f" should have at least one of {mozilla_config.certificate_types}."
        )

    # Validate the signature algorithms
    found_sig_algorithm = False
    for sig_algorithm in mozilla_config.certificate_signatures:
        if sig_algorithm in deployed_signature_algorithms:
            found_sig_algorithm = True
            break
    if not found_sig_algorithm:
        issues_with_certificates["certificate_signatures"] = (
            f"Deployed certificate signatures are {deployed_signature_algorithms},"
            f" should have at least one of {mozilla_config.certificate_signatures}."
        )

    # TODO(AD): Maybe add check for ocsp_staple but that one seems optional in https://ssl-config.mozilla.org/

    return issues_with_certificates
