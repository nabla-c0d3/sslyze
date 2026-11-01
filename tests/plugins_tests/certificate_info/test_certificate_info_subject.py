"""Offline tests for the subject used by the certificate_info plugin during validation.

These tests exercise ``CertificateInfoImplementation.result_for_completed_scan_jobs()`` with fabricated scan job
results and a local trust store, so no network connection is ever opened. They cover how the configured SNI value is
turned into the ``DNSName``/``IPAddress`` subject passed to the certificate deployment analyzer:

* a DNS SNI is validated as a DNS name, including a single trailing root dot;
* an IP literal SNI is validated as an IP address even when the target's resolved IP is written differently
  (eg. an expanded IPv6 address);
* a custom SNI keeps overriding the resolved hostname / target IP;
* a mismatching SNI makes the path validation fail instead of raising.
"""

from __future__ import annotations

import socket
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Callable, List, Optional, Union

import pytest
from cryptography import x509
from cryptography.x509 import DNSName, IPAddress
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sslyze.plugins.certificate_info.implementation import CertificateInfoImplementation
from sslyze.plugins.certificate_info.trust_stores.trust_store import PathValidationResult, TrustStore
from sslyze.plugins.certificate_info.trust_stores.trust_store_repository import TrustStoresRepository
from sslyze.plugins.plugin_base import ScanJobResult
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerConnectivityInfo,
    ServerTlsProbingResult,
    TlsVersionEnum,
)
from sslyze.server_setting import HttpProxySettings, ServerNetworkConfiguration, ServerNetworkLocation
from tests.plugins_tests.certificate_info import test_trust_store

GOOGLE_CHAIN = test_trust_store.GOOGLE_DOT_COM_CERT_CHAIN_ON_11_2022
GOOGLE_CHAIN_VALIDATION_TIME = datetime(2022, 11, 6, tzinfo=timezone.utc)


class _TrustStoreRepository:
    def __init__(self, trust_stores: List[TrustStore]) -> None:
        self._trust_stores = trust_stores

    def get_all_stores(self) -> List[TrustStore]:
        return list(self._trust_stores)


@pytest.fixture
def install_trust_stores(monkeypatch: pytest.MonkeyPatch) -> Callable[[List[TrustStore]], None]:
    def _install(trust_stores: List[TrustStore]) -> None:
        monkeypatch.setattr(
            TrustStoresRepository, "get_default", classmethod(lambda cls: _TrustStoreRepository(trust_stores))
        )

    return _install


@pytest.fixture(autouse=True)
def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove these tests are offline: every socket entry point raises immediately."""

    def _blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access is forbidden in these offline tests")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)


@pytest.fixture
def install_google_chain_trust_store(
    monkeypatch: pytest.MonkeyPatch, install_trust_stores: Callable[[List[TrustStore]], None]
) -> TrustStore:
    """Use the real Mozilla store, but verify the 2022 Google chain at a time when it was valid."""
    trust_store = TrustStore(
        path=TrustStoresRepository._DEFAULT_TRUST_STORES_PATH / "mozilla_nss.pem",
        name="Mozilla",
        version="123",
    )
    original_verify = TrustStore.verify_certificate_chain

    def _verify_at_2022(
        self: TrustStore,
        certificate_chain_as_pem: List[str],
        server_subject: Union[DNSName, IPAddress],
        validation_time: Optional[datetime] = None,
    ) -> PathValidationResult:
        return original_verify(self, certificate_chain_as_pem, server_subject, GOOGLE_CHAIN_VALIDATION_TIME)

    monkeypatch.setattr(TrustStore, "verify_certificate_chain", _verify_at_2022)
    install_trust_stores([trust_store])
    return trust_store


def _server_info(
    hostname: str,
    sni: str,
    ip_address_as_string: Optional[str],
    proxy: Optional[HttpProxySettings] = None,
) -> ServerConnectivityInfo:
    location = ServerNetworkLocation(
        hostname=hostname,
        port=443,
        ip_address=ip_address_as_string,
        http_proxy_settings=proxy,
    )
    return ServerConnectivityInfo(
        server_location=location,
        network_configuration=ServerNetworkConfiguration(tls_server_name_indication=sni),
        tls_probing_result=ServerTlsProbingResult(
            highest_tls_version_supported=TlsVersionEnum.TLS_1_3,
            cipher_suite_supported="TLS_AES_128_GCM_SHA256",
            client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
            supports_ecdh_key_exchange=True,
        ),
    )


def _scan_job_results(certificate_chain_as_pem: List[str]) -> List[ScanJobResult]:
    # Three SNI-enabled deployments and one SNI-disabled deployment, as produced by scan_jobs_for_scan_command().
    results = [
        ScanJobResult(_return_value=(certificate_chain_as_pem, None, None, True), _exception=None) for _ in range(3)
    ]
    results.append(ScanJobResult(_return_value=(certificate_chain_as_pem, None, None, False), _exception=None))
    return results


def _mint_ip_certificate_chain(tmp_path: Path, ip_sans: List[str]) -> tuple[List[str], Path]:
    """Mint a CA and a leaf certificate with the supplied IP subjectAltName values; return PEM chain and CA path."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SSLyze subject normalization test CA")])
    ca_key_identifier = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=True,
                crl_sign=True,
            ),
            critical=True,
        )
        .add_extension(ca_key_identifier, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "subject-normalization.test")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_address(value)) for value in ip_sans]), critical=False
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = tmp_path / "subject-normalization-ca.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    chain = [
        leaf_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        ca_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    ]
    return chain, ca_path


def _minted_trust_store(ca_path: Path) -> TrustStore:
    return TrustStore(path=ca_path, name="Subject normalization test CA", version="1")


class TestCertificateInfoSubjectForValidation:
    def test_dns_sni_is_validated_as_hostname(
        self,
        install_google_chain_trust_store: TrustStore,
    ) -> None:
        # Given a server with a DNS SNI and a resolved IP that is unrelated to the hostname
        server_info = _server_info("www.google.com", "www.google.com", "192.0.2.10")

        # When running the certificate analysis
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(
            server_info, _scan_job_results(GOOGLE_CHAIN)
        )

        # Then the certificate is validated against the SNI hostname
        deployment = result.certificate_deployments[0]
        assert deployment.verified_certificate_chain
        assert deployment.path_validation_results[0].was_validation_successful
        assert result.hostname_used_for_server_name_indication == "www.google.com"

    def test_custom_sni_keeps_overriding_the_target(
        self,
        install_google_chain_trust_store: TrustStore,
    ) -> None:
        # Given a target hostname/IP that differs from the configured SNI
        server_info = _server_info("origin.example", "www.google.com", "192.0.2.10")

        # When running the certificate analysis
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(
            server_info, _scan_job_results(GOOGLE_CHAIN)
        )

        # Then the custom SNI is still the subject being validated
        assert result.certificate_deployments[0].path_validation_results[0].was_validation_successful
        assert result.hostname_used_for_server_name_indication == "www.google.com"
        assert server_info.server_location.hostname == "origin.example"

    def test_ipv4_sni_is_validated_as_an_ip(
        self,
        tmp_path: Path,
        install_trust_stores: Callable[[List[TrustStore]], None],
    ) -> None:
        # Given a certificate with an IPv4 subjectAltName and a matching IP SNI
        chain, ca_path = _mint_ip_certificate_chain(tmp_path, ["192.0.2.10"])
        install_trust_stores([_minted_trust_store(ca_path)])
        server_info = _server_info("192.0.2.10", "192.0.2.10", "192.0.2.10")

        # When running the certificate analysis
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(server_info, _scan_job_results(chain))

        # Then the IP SNI is validated as an IP address
        assert result.certificate_deployments[0].path_validation_results[0].was_validation_successful

    def test_expanded_ipv6_sni_is_validated_as_the_canonical_ip(
        self,
        tmp_path: Path,
        install_trust_stores: Callable[[List[TrustStore]], None],
    ) -> None:
        # Given an IPv6 SNI written in expanded form while the target resolved to the compressed form
        expanded_sni = "2001:0db8:0000:0000:0000:0000:0000:0001"
        chain, ca_path = _mint_ip_certificate_chain(tmp_path, ["2001:db8::1"])
        install_trust_stores([_minted_trust_store(ca_path)])
        server_info = _server_info(expanded_sni, expanded_sni, "2001:db8::1")

        # When running the certificate analysis
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(server_info, _scan_job_results(chain))

        # Then the expanded literal is validated as the canonical IP address, not as a DNS name
        assert result.certificate_deployments[0].path_validation_results[0].was_validation_successful
        # And the SNI sent on the wire / reported to users is left untouched
        assert result.hostname_used_for_server_name_indication == expanded_sni

    def test_sni_with_a_single_trailing_root_dot_is_validated(
        self,
        install_google_chain_trust_store: TrustStore,
    ) -> None:
        # Given a DNS SNI with the absolute/root dot
        server_info = _server_info("www.google.com.", "www.google.com.", "192.0.2.10")

        # When running the certificate analysis
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(
            server_info, _scan_job_results(GOOGLE_CHAIN)
        )

        # Then the trailing root dot is removed for validation only
        assert result.certificate_deployments[0].path_validation_results[0].was_validation_successful
        # And the original SNI and location hostname are preserved
        assert result.hostname_used_for_server_name_indication == "www.google.com."
        assert server_info.server_location.hostname == "www.google.com."

    def test_proxy_scan_without_a_resolved_ip_uses_the_sni(
        self,
        install_google_chain_trust_store: TrustStore,
    ) -> None:
        # Given a scan going through a proxy: ServerNetworkLocation.ip_address is None
        server_info = _server_info(
            "www.google.com",
            "www.google.com",
            None,
            proxy=HttpProxySettings(hostname="proxy.test", port=8080),
        )
        assert server_info.server_location.ip_address is None

        # When running the certificate analysis
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(
            server_info, _scan_job_results(GOOGLE_CHAIN)
        )

        # Then the SNI hostname is validated normally
        assert result.certificate_deployments[0].path_validation_results[0].was_validation_successful
        assert result.hostname_used_for_server_name_indication == "www.google.com"

    def test_mismatching_sni_fails_validation_without_raising(
        self,
        install_google_chain_trust_store: TrustStore,
    ) -> None:
        # Given an SNI that does not match the certificate
        server_info = _server_info("notgoogle.com", "notgoogle.com", "192.0.2.10")

        # When running the certificate analysis, it does not raise
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(
            server_info, _scan_job_results(GOOGLE_CHAIN)
        )

        # Then the path validation reports the hostname mismatch
        deployment = result.certificate_deployments[0]
        assert deployment.verified_certificate_chain is None
        assert deployment.path_validation_results
        assert not deployment.path_validation_results[0].was_validation_successful
        assert deployment.path_validation_results[0].validation_error
        assert "no matching subjectAltName" in deployment.path_validation_results[0].validation_error
        assert result.hostname_used_for_server_name_indication == "notgoogle.com"

    def test_ip_like_dns_sni_is_not_coerced_into_an_ip(
        self,
        install_google_chain_trust_store: TrustStore,
    ) -> None:
        # Given an SNI that looks numeric but is not a valid IP address
        server_info = _server_info("192.0.2.10.5", "192.0.2.10.5", "192.0.2.10")

        # When running the certificate analysis, it does not raise an ip_address() error
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(
            server_info, _scan_job_results(GOOGLE_CHAIN)
        )

        # Then it is treated as a DNS name and fails hostname validation
        deployment = result.certificate_deployments[0]
        assert not deployment.path_validation_results[0].was_validation_successful
        assert deployment.path_validation_results[0].validation_error
        assert "no matching subjectAltName" in deployment.path_validation_results[0].validation_error

    @pytest.mark.parametrize(
        ("sni", "certificate_san", "target_ip"),
        [
            ("192.0.2.10", "192.0.2.10", "192.0.2.99"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", "2001:db8::2"),
        ],
        ids=["ipv4", "expanded-ipv6"],
    )
    def test_numeric_custom_sni_is_validated_as_an_ip(
        self,
        tmp_path: Path,
        install_trust_stores: Callable[[List[TrustStore]], None],
        sni: str,
        certificate_san: str,
        target_ip: str,
    ) -> None:
        # Given a numeric SNI that differs from the connection target and is written in a non-canonical form
        chain, ca_path = _mint_ip_certificate_chain(tmp_path, [certificate_san])
        install_trust_stores([_minted_trust_store(ca_path)])
        server_info = _server_info("origin.example", sni, target_ip)

        # When running the certificate analysis
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(server_info, _scan_job_results(chain))

        # Then the SNI literal is validated as an IP address, not as a DNS name
        assert result.certificate_deployments[0].path_validation_results[0].was_validation_successful
        # And neither the SNI sent on the wire nor the connection target is rewritten
        assert result.hostname_used_for_server_name_indication == sni
        assert server_info.server_location.hostname == "origin.example"

    @pytest.mark.parametrize(
        ("sni", "certificate_san"),
        [
            ("192.0.2.10", "192.0.2.10"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ],
        ids=["ipv4", "expanded-ipv6"],
    )
    def test_numeric_sni_behind_a_proxy_without_resolved_ip(
        self,
        tmp_path: Path,
        install_trust_stores: Callable[[List[TrustStore]], None],
        sni: str,
        certificate_san: str,
    ) -> None:
        # Given a proxy scan, for which ServerNetworkLocation.ip_address is None
        chain, ca_path = _mint_ip_certificate_chain(tmp_path, [certificate_san])
        install_trust_stores([_minted_trust_store(ca_path)])
        server_info = _server_info(
            "www.example.com",
            sni,
            None,
            proxy=HttpProxySettings(hostname="proxy.test", port=8080),
        )
        assert server_info.server_location.ip_address is None

        # When running the certificate analysis
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(server_info, _scan_job_results(chain))

        # Then the numeric SNI is still validated as an IP address
        assert result.certificate_deployments[0].path_validation_results[0].was_validation_successful
        assert result.hostname_used_for_server_name_indication == sni

    def test_canonical_ip_sni_control_case(
        self,
        tmp_path: Path,
        install_trust_stores: Callable[[List[TrustStore]], None],
    ) -> None:
        # Given a canonical IP SNI matching the resolved IP, the pre-existing behaviour must be preserved
        chain, ca_path = _mint_ip_certificate_chain(tmp_path, ["2001:db8::1"])
        install_trust_stores([_minted_trust_store(ca_path)])
        server_info = _server_info("2001:db8::1", "2001:db8::1", "2001:db8::1")

        # When running the certificate analysis
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(server_info, _scan_job_results(chain))

        # Then the IP subject is validated as before
        assert result.certificate_deployments[0].path_validation_results[0].was_validation_successful
        assert result.hostname_used_for_server_name_indication == "2001:db8::1"

    @pytest.mark.parametrize(
        ("sni", "certificate_san"),
        [
            ("192.0.2.10", "192.0.2.11"),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::2"),
        ],
        ids=["ipv4", "expanded-ipv6"],
    )
    def test_mismatching_ip_san_is_a_validation_failure_not_an_acceptance(
        self,
        tmp_path: Path,
        install_trust_stores: Callable[[List[TrustStore]], None],
        sni: str,
        certificate_san: str,
    ) -> None:
        # Given a certificate whose IP subjectAltName does not match the numeric SNI
        chain, ca_path = _mint_ip_certificate_chain(tmp_path, [certificate_san])
        install_trust_stores([_minted_trust_store(ca_path)])
        server_info = _server_info("origin.example", sni, "192.0.2.99")

        # When running the certificate analysis, it returns a result instead of raising
        result = CertificateInfoImplementation.result_for_completed_scan_jobs(server_info, _scan_job_results(chain))

        # Then the mismatch is reported as a failed path validation
        deployment = result.certificate_deployments[0]
        assert deployment.verified_certificate_chain is None
        assert not deployment.path_validation_results[0].was_validation_successful
        assert deployment.path_validation_results[0].validation_error
        assert "no matching subjectAltName" in deployment.path_validation_results[0].validation_error
        assert result.hostname_used_for_server_name_indication == sni

    @pytest.mark.parametrize("sni", ["", "."], ids=["empty", "root-dot-only"])
    def test_malformed_sni_is_not_normalized_into_a_valid_name(
        self,
        install_google_chain_trust_store: TrustStore,
        sni: str,
    ) -> None:
        # Given an SNI that has no DNS label at all
        server_info = _server_info("www.example.com", sni, "192.0.2.10")

        # When running the certificate analysis, it is still rejected
        with pytest.raises(ValueError):
            CertificateInfoImplementation.result_for_completed_scan_jobs(server_info, _scan_job_results(GOOGLE_CHAIN))

    def test_malformed_dns_sni_with_double_dot_still_fails(
        self,
        install_google_chain_trust_store: TrustStore,
    ) -> None:
        # Given a malformed DNS SNI with two trailing dots
        server_info = _server_info("www.google.com", "www.google.com..", "192.0.2.10")

        # When running the certificate analysis, the invalid domain is still rejected
        with pytest.raises(ValueError):
            CertificateInfoImplementation.result_for_completed_scan_jobs(server_info, _scan_job_results(GOOGLE_CHAIN))
