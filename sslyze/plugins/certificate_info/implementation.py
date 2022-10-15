from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Tuple

import nassl

from sslyze.errors import TlsHandshakeFailed
from sslyze.plugins.certificate_info._cert_chain_analyzer import (
    CertificateDeploymentAnalyzer,
    CertificateDeploymentAnalysisResult,
)
from sslyze.plugins.certificate_info._cli_connector import _CertificateInfoCliConnector
from sslyze.plugins.certificate_info._get_cert_chain import get_certificate_chain, ArgumentsToGetCertificateChain
from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore
from sslyze.plugins.certificate_info.trust_stores.trust_store_repository import TrustStoresRepository
from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanJob,
    ScanCommandResult,
    ScanCommandExtraArgument,
    ScanJobResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


@dataclass(frozen=True)
class CertificateInfoExtraArgument(ScanCommandExtraArgument):
    """Additional configuration for running the certificate_info scan command.

    Attributes:
        custom_ca_file: The path to a custom trust store file to use for certificate validation. The file should contain
            PEM-formatted root certificates.
    """

    custom_ca_file: Path

    def __post_init__(self) -> None:
        if not self.custom_ca_file.is_file():
            raise ValueError(f'Could not open supplied CA file at "{self.custom_ca_file}"')


@dataclass(frozen=True)
class CertificateInfoScanResult(ScanCommandResult):
    """The result of retrieving and analyzing a server's certificates to verify their validity.

    Attributes:
        hostname_used_for_server_name_indication: The hostname sent by SSLyze as the Server Name Indication extension.
        certificate_deployments: A list of leaf certificates detected by SSLyze and the corresponding analysis. Most
            servers only deploy one leaf certificate, but some websites (such as Facebook) return different leaf
            certificates depending on the client, as a way to maximize compatibility with older clients/devices.
    """

    hostname_used_for_server_name_indication: str
    certificate_deployments: List[CertificateDeploymentAnalysisResult]


class CertificateInfoImplementation(ScanCommandImplementation[CertificateInfoScanResult, None]):
    """Retrieve and analyze a server's certificate(s) to verify its validity."""

    cli_connector_cls = _CertificateInfoCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[CertificateInfoExtraArgument] = None
    ) -> List[ScanJob]:
        custom_ca_file = extra_arguments.custom_ca_file if extra_arguments else None

        # Try to retrieve different certificates from the server by having SSLyze's TLS handshake look like different
        # kinds of clients
        call_arguments: List[ArgumentsToGetCertificateChain] = []
        if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
            # Get the default certificate chain sent to clients using TLS 1.3
            call_arguments.append((server_info, custom_ca_file, TlsVersionEnum.TLS_1_3, None))

            # Get the other certificate chains sent to clients using TLS 1.2 that support or don't support RSA
            call_arguments.append((server_info, custom_ca_file, TlsVersionEnum.TLS_1_2, "RSA"))
            call_arguments.append((server_info, custom_ca_file, TlsVersionEnum.TLS_1_2, "ALL:-RSA"))
        else:
            # Get the certificate chains sent to clients that support or don't support RSA
            call_arguments.append((server_info, custom_ca_file, None, None))
            call_arguments.append((server_info, custom_ca_file, None, "RSA"))
            call_arguments.append((server_info, custom_ca_file, None, "ALL:-RSA"))

        # The custom_ca_file is not needed by get_certificate_chain() but we have to pass it anyway so we can eventually
        # use it in result_for_completed_scan_jobs()
        scan_jobs = [
            ScanJob(function_to_call=get_certificate_chain, function_arguments=call_arg) for call_arg in call_arguments
        ]
        return scan_jobs

    _EXPECTED_SCAN_JOB_RESULTS_COUNT = 3

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> CertificateInfoScanResult:
        if len(scan_job_results) != cls._EXPECTED_SCAN_JOB_RESULTS_COUNT:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        # Only keep certificate deployments that are different
        # Leaf certificate => certificate chain, OCSP response
        all_configured_certificate_chains: Dict[str, Tuple[List[str], Optional[nassl._nassl.OCSP_RESPONSE]]] = {}
        all_handshake_failed_exceptions: List[TlsHandshakeFailed] = []
        custom_ca_file = None
        for completed_job in scan_job_results:
            try:
                received_chain_as_pem, ocsp_response, custom_ca_file = completed_job.get_result()
            except TlsHandshakeFailed as exc:
                # Can happen when trying to connect with specific cipher suites (such as RSA or non-RSA)
                # or when connectivity is bad
                all_handshake_failed_exceptions.append(exc)
                continue

            if not received_chain_as_pem:
                raise ValueError("Should never happen")

            all_configured_certificate_chains[received_chain_as_pem[0]] = received_chain_as_pem, ocsp_response

        if len(all_handshake_failed_exceptions) == cls._EXPECTED_SCAN_JOB_RESULTS_COUNT:
            # All TLS handshakes failed: bad connectivity to the server
            # Re-raise one of the handshake exceptions
            raise all_handshake_failed_exceptions[0]

        if not all_configured_certificate_chains:
            raise ValueError("Should never happen")

        # Then validate each certificate/chain deployment
        all_trust_stores = TrustStoresRepository.get_default().get_all_stores()
        if custom_ca_file:
            all_trust_stores.append(TrustStore(custom_ca_file, "Supplied CA file", "N/A"))

        analyzed_deployments = []
        name_to_use_for_hostname_validation = server_info.network_configuration.tls_server_name_indication
        for received_chain_as_pem, ocsp_response in all_configured_certificate_chains.values():
            deployment_analyzer = CertificateDeploymentAnalyzer(
                server_hostname=name_to_use_for_hostname_validation,
                server_certificate_chain_as_pem=received_chain_as_pem,
                server_ocsp_response=ocsp_response,
                trust_stores_for_validation=all_trust_stores,
            )
            analysis_result = deployment_analyzer.perform()
            analyzed_deployments.append(analysis_result)

        # All done
        return CertificateInfoScanResult(
            hostname_used_for_server_name_indication=name_to_use_for_hostname_validation,
            certificate_deployments=analyzed_deployments,
        )
