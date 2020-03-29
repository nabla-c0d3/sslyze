from concurrent.futures import Future
from operator import attrgetter

from dataclasses import dataclass

from sslyze.connection_helpers.tls_connection import NoCiphersAvailableBugInSSlyze
from sslyze.plugins.openssl_cipher_suites._cli_connector import _CipherSuitesCliConnector
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    connect_with_cipher_suite,
    CipherSuiteRejectedByServer,
    CipherSuiteAcceptedByServer,
    PreferredCipherSuite,
    get_preferred_cipher_suite,
)
from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuitesRepository
from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandResult,
    ScanJob,
    ScanCommandExtraArguments,
    ScanCommandWrongUsageError,
)
from typing import ClassVar, Optional
from typing import List

from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


@dataclass(frozen=True)
class CipherSuitesScanResult(ScanCommandResult):
    """The result of testing a server for cipher suites with a specific version of SSL/TLS.

    Attributes:
        tls_version_used: The SSL/TLS version used to connect to the server.
        accepted_ciphers: The list of cipher suites supported supported by both SSLyze and the server.
        rejected_ciphers: The list of cipher suites supported by SSLyze that were rejected by the server.
        cipher_suite_preferred_by_server: The server's preferred cipher suite among all the cipher suites supported by
            SSLyze. ``None`` if the server follows the client's preference or if none of SSLyze's cipher suites are
            supported by the server.
    """

    tls_version_used: TlsVersionEnum

    cipher_suite_preferred_by_server: Optional[CipherSuiteAcceptedByServer]
    accepted_cipher_suites: List[CipherSuiteAcceptedByServer]
    rejected_cipher_suites: List[CipherSuiteRejectedByServer]

    @property
    def is_tls_protocol_version_supported(self) -> bool:
        """Is the SSL/TLS version used to connect the server supported by it?
        """
        return True if self.accepted_cipher_suites else False


class _Sslv20CliConnector(_CipherSuitesCliConnector):

    _cli_option = "sslv2"
    _cli_description = "Test a server for SSL 2.0 support."
    _title_in_output = "SSL 2.0 Cipher suites"


class _Sslv30CliConnector(_CipherSuitesCliConnector):

    _cli_option = "sslv3"
    _cli_description = "Test a server for SSL 3.0 support."
    _title_in_output = "SSL 3.0 Cipher suites"


class _Tlsv10CliConnector(_CipherSuitesCliConnector):

    _cli_option = "tlsv1"
    _cli_description = "Test a server for TLS 1.0 support."
    _title_in_output = "TLS 1.0 Cipher suites"


class _Tlsv11CliConnector(_CipherSuitesCliConnector):

    _cli_option = "tlsv1_1"
    _cli_description = "Test a server for TLS 1.1 support."
    _title_in_output = "TLS 1.1 Cipher suites"


class _Tlsv12CliConnector(_CipherSuitesCliConnector):

    _cli_option = "tlsv1_2"
    _cli_description = "Test a server for TLS 1.2 support."
    _title_in_output = "TLS 1.2 Cipher suites"


class _Tlsv13CliConnector(_CipherSuitesCliConnector):

    _cli_option = "tlsv1_3"
    _cli_description = "Test a server for TLS 1.3 support."
    _title_in_output = "TLS 1.3 Cipher suites"


class _CipherSuitesScanImplementation(ScanCommandImplementation[CipherSuitesScanResult, None]):

    # The SSL version corresponding to the scan command
    _tls_version: ClassVar[TlsVersionEnum]

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        # Run one job per cipher suite to test for
        all_cipher_suites_to_test = CipherSuitesRepository.get_all_cipher_suites(cls._tls_version)
        scan_jobs = [
            ScanJob(
                function_to_call=connect_with_cipher_suite,
                function_arguments=[server_info, cls._tls_version, cipher_suite],
            )
            for cipher_suite in all_cipher_suites_to_test
        ]
        # Run an additional job to find the preferred cipher suite
        scan_jobs.append(
            ScanJob(function_to_call=get_preferred_cipher_suite, function_arguments=[server_info, cls._tls_version])
        )
        return scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> CipherSuitesScanResult:
        expected_scan_jobs_count = len(CipherSuitesRepository.get_all_cipher_suites(cls._tls_version)) + 1
        if len(completed_scan_jobs) != expected_scan_jobs_count:
            raise RuntimeError(f"Unexpected number of scan jobs received: {completed_scan_jobs}")

        preferred_cipher_suite_openssl_name = None
        accepted_cipher_suites = []
        rejected_cipher_suites = []
        for completed_job in completed_scan_jobs:
            try:
                cipher_suite_result = completed_job.result()
            except NoCiphersAvailableBugInSSlyze:
                # Happens when we passed a cipher suite and a TLS version that are not supported together by OpenSSL
                # Swallowing this exception makes it easier as we can just always use the ALL:COMPLEMENTOFALL OpenSSL
                # cipher string instead of having to figure out exactly which cipher suites are supported by which
                # versions
                continue
            if isinstance(cipher_suite_result, CipherSuiteAcceptedByServer):
                accepted_cipher_suites.append(cipher_suite_result)
            elif isinstance(cipher_suite_result, CipherSuiteRejectedByServer):
                rejected_cipher_suites.append(cipher_suite_result)
            elif isinstance(cipher_suite_result, PreferredCipherSuite):
                preferred_cipher_suite_openssl_name = cipher_suite_result.cipher_suite_openssl_name
            else:
                raise ValueError("Should never happen")

        # Sort all the lists
        accepted_cipher_suites.sort(key=attrgetter("cipher_suite.name"), reverse=True)
        rejected_cipher_suites.sort(key=attrgetter("cipher_suite.name"), reverse=True)

        # Find the preferred cipher suite among all the accepted cipher suites
        if preferred_cipher_suite_openssl_name is None:
            preferred_cipher_suite = None
        else:
            openssl_name_to_accepted_cipher_suite = {
                acc_cipher_suite.cipher_suite.openssl_name: acc_cipher_suite
                for acc_cipher_suite in accepted_cipher_suites
            }
            preferred_cipher_suite = openssl_name_to_accepted_cipher_suite[preferred_cipher_suite_openssl_name]

        # Generate the results
        return CipherSuitesScanResult(
            tls_version_used=cls._tls_version,
            cipher_suite_preferred_by_server=preferred_cipher_suite,
            accepted_cipher_suites=accepted_cipher_suites,
            rejected_cipher_suites=rejected_cipher_suites,
        )


class Sslv20ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for SSL 2.0 support.
    """

    cli_connector_cls = _Sslv20CliConnector
    _tls_version = TlsVersionEnum.SSL_2_0


class Sslv30ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for SSL 3.0 support.
    """

    cli_connector_cls = _Sslv30CliConnector
    _tls_version = TlsVersionEnum.SSL_3_0


class Tlsv10ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for TLS 1.0 support.
    """

    cli_connector_cls = _Tlsv10CliConnector
    _tls_version = TlsVersionEnum.TLS_1_0


class Tlsv11ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for TLS 1.1 support.
    """

    cli_connector_cls = _Tlsv11CliConnector
    _tls_version = TlsVersionEnum.TLS_1_1


class Tlsv12ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for TLS 1.2 support.
    """

    cli_connector_cls = _Tlsv12CliConnector
    _tls_version = TlsVersionEnum.TLS_1_2


class Tlsv13ScanImplementation(_CipherSuitesScanImplementation):
    """Test a server for TLS 1.3 support.
    """

    cli_connector_cls = _Tlsv13CliConnector
    _tls_version = TlsVersionEnum.TLS_1_3
