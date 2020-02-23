from concurrent.futures import Future
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, List

from cryptography.x509 import Certificate
from nassl.ocsp_response import OcspResponseStatusEnum

from sslyze.plugins.certificate_info.cert_chain_analyzer import CertificateChainDeploymentAnalyzer
from sslyze.plugins.certificate_info.cli_connector import _CertificateInfoCliConnector
from sslyze.plugins.certificate_info.get_cert_chain import get_and_verify_certificate_chain, PathValidationResult
from sslyze.plugins.plugin_base import ScanCommandImplementation, ScanJob, ScanCommandResult, ScanCommandExtraArguments
from sslyze.plugins.certificate_info.trust_stores.trust_store import TrustStore
from sslyze.plugins.certificate_info.trust_stores.trust_store_repository import TrustStoresRepository
from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class CertificateInfoExtraArguments(ScanCommandExtraArguments):
    """Additional configuration for running the CERTIFICATE_INFO scan command.

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
    """The result of retrieving and analyzing a  certificate(s) to verify its validity.

    Any certificate available as an attribute is parsed using the cryptography module; documentation is available at
    https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object

    Attributes:
        hostname_used_for_server_name_indication: The hostname sent by sslyze as the Server Name Indication extension.
        received_certificate_chain: The certificate chain sent by the server; index 0 is the leaf certificate.
        verified_certificate_chain: The verified certificate chain returned by OpenSSL for one of the trust stores
            packaged within SSLyze. Will be None if the validation failed with all of the available trust stores
            (Apple, Mozilla, etc.). This is essentially a shortcut to
            path_validation_result_list[0].verified_certificate_chain.
        path_validation_results: The result of validating the server's
            certificate chain using each trust store that is packaged with SSLyze (Mozilla, Apple, etc.).
            If for a given trust store, the validation was successful, the verified certificate chain built by OpenSSL
            can be retrieved from the PathValidationResult.
        leaf_certificate_subject_matches_hostname
        leaf_certificate_is_ev: True if the leaf certificate is Extended Validation according to Mozilla.
        leaf_certificate_has_must_staple_extension
        leaf_certificate_signed_certificate_timestamps_count (Optional[int]): The number of Signed Certificate
            Timestamps (SCTs) for Certificate Transparency embedded in the leaf certificate. None if the version of
            OpenSSL installed on the system is too old to be able to parse the SCT extension.
        received_chain_has_valid_order
        received_chain_contains_anchor_certificate: True if the server included the anchor/root
            certificate in the chain it sends back to clients. None if the verified chain could not be built.
        verified_chain_has_sha1_signature (Optional[bool]): True if any of the leaf or intermediate certificates are
            signed using the SHA-1 algorithm. None if the verified chain could not be built.
        verified_chain_has_legacy_symantec_anchor: True if the certificate chain contains a distrusted Symantec anchor
            (https://blog.qualys.com/ssllabs/2017/09/26/google-and-mozilla-deprecating-existing-symantec-certificates).
            None if the verified chain could not be built.
        ocsp_response (Optional[Dict[Text, Any]]): The OCSP response returned by the server. None if no response was
            sent by the server.
        ocsp_response_status: The status of the OCSP response returned by the server. None if no response was sent by
            the server.
        ocsp_response_is_trusted: True if the OCSP response is trusted using the Mozilla trust store.
            None if no OCSP response was sent by the server.

    """

    hostname_used_for_server_name_indication: str
    received_certificate_chain: List[Certificate]
    path_validation_results: List[PathValidationResult]

    leaf_certificate_subject_matches_hostname: bool
    leaf_certificate_has_must_staple_extension: bool
    leaf_certificate_is_ev: bool
    leaf_certificate_signed_certificate_timestamps_count: Optional[int]

    received_chain_has_valid_order: bool
    received_chain_contains_anchor_certificate: Optional[bool]

    verified_chain_has_sha1_signature: Optional[bool]
    verified_chain_has_legacy_symantec_anchor: Optional[bool]

    ocsp_response: str  # TODO
    ocsp_response_is_trusted: Optional[bool]
    ocsp_response_status: Optional[OcspResponseStatusEnum]

    @property
    def verified_certificate_chain(self) -> Optional[List[Certificate]]:
        for path_result in self.path_validation_results:
            if path_result.was_validation_successful:
                return path_result.verified_certificate_chain
        return None


# TODO(AD): Use the new nassl function to check certificate
class CertificateInfoImplementation(ScanCommandImplementation):
    """Retrieve and analyze a server's certificate(s) to verify its validity.
    """

    cli_connector_cls = _CertificateInfoCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[CertificateInfoExtraArguments] = None
    ) -> List[ScanJob]:
        final_trust_store_list = TrustStoresRepository.get_default().get_all_stores()
        if extra_arguments:
            final_trust_store_list.append(TrustStore(extra_arguments.custom_ca_file, "Supplied CA file", "N/A"))

        # Run one job per trust store to test for
        scan_jobs = [
            ScanJob(function_to_call=get_and_verify_certificate_chain, function_arguments=[server_info, trust_store])
            for trust_store in final_trust_store_list
        ]
        return scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
        # Store the results as they come
        path_validation_results = []
        ocsp_response = None
        received_chain = None
        for completed_job in completed_scan_jobs:
            received_chain, validation_result, _ocsp_response = completed_job.result()
            path_validation_results.append(validation_result)

            # Keep the OCSP response if the validation was successful and a response was returned
            if _ocsp_response:
                ocsp_response = _ocsp_response

        if not received_chain:
            raise ValueError("Should never happen")

        # Sort the path_validation_result_list so the same successful_trust_store always get picked for a given server
        # because threading timings change the order of path_validation_result_list
        def sort_function(path_validation: PathValidationResult) -> str:
            return path_validation.trust_store.name.lower()

        path_validation_results.sort(key=sort_function)

        verified_certificate_chain = None
        trust_store_used_to_build_verified_chain = None
        for path_result in path_validation_results:
            if path_result.was_validation_successful:
                verified_certificate_chain = path_result.verified_certificate_chain
                trust_store_used_to_build_verified_chain = path_result.trust_store

        # Analyze the certificate chain deployment
        analyzer = CertificateChainDeploymentAnalyzer(
            server_hostname=server_info.network_configuration.tls_server_name_indication,
            received_chain=received_chain,
            verified_chain=verified_certificate_chain,
            trust_store_used_to_build_verified_chain=trust_store_used_to_build_verified_chain,
            received_ocsp_response=ocsp_response,
        )
        analysis_result = analyzer.perform()

        return CertificateInfoScanResult(
            hostname_used_for_server_name_indication=server_info.network_configuration.tls_server_name_indication,
            received_certificate_chain=received_chain,
            path_validation_results=path_validation_results,
            ocsp_response=ocsp_response.as_dict() if ocsp_response else None,
            # The CertificateChainDeploymentAnalysisResult and the CertificateInfoScanResult have the same field names
            **asdict(analysis_result),
        )
