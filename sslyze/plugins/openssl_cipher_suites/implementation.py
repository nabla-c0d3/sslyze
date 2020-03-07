from concurrent.futures import Future
from operator import attrgetter

from dataclasses import dataclass

from nassl.ssl_client import OpenSslVersionEnum

from sslyze.connection_helpers.tls_connection import NoCiphersAvailableBugInSSlyze
from sslyze.plugins.openssl_cipher_suites._cli_connector import _CipherSuitesCliConnector
from sslyze.plugins.openssl_cipher_suites._test_cipher_suite import (
    connect_with_cipher_suite,
    CipherSuiteRejectedByServer,
    CipherSuiteAcceptedByServer,
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

from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class CipherSuitesScanResult(ScanCommandResult):
    """The result of running a CipherSuiteScanCommand on a specific server.

    Attributes:
        accepted_ciphers: The list of cipher suites supported supported by both SSLyze and the server.
        rejected_ciphers: The list of cipher suites supported by SSLyze that were rejected by the server.
        errored_ciphers: The list of cipher suites supported by SSLyze that triggered an unexpected error during the
            TLS handshake with the server.
        preferred_cipher: The server's preferred cipher suite among all the cipher suites supported by SSLyze.
            `None` if the server follows the client's preference or if none of SSLyze's cipher suites are supported by
            the server.
    """

    tls_version_used: OpenSslVersionEnum

    cipher_suite_preferred_by_server: Optional[CipherSuiteAcceptedByServer]
    accepted_cipher_suites: List[CipherSuiteAcceptedByServer]
    rejected_cipher_suites: List[CipherSuiteRejectedByServer]

    @property
    def is_tls_protocol_version_supported(self) -> bool:
        """Is the SSL/TLS version used to connect the server supported by it?
        """
        return True if self.accepted_cipher_suites else False

    @property
    def follows_cipher_suite_preference_from_client(self) -> bool:
        """Did the server the pick the cipher suite preferred by the client?
        """
        return True if self.cipher_suite_preferred_by_server is None else False


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
    _tls_version: ClassVar[OpenSslVersionEnum]

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
        return scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> CipherSuitesScanResult:
        # Store the results as they come
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
            else:
                raise ValueError("Should never happen")

        # Sort all the lists
        accepted_cipher_suites.sort(key=attrgetter("cipher_suite.name"), reverse=True)
        rejected_cipher_suites.sort(key=attrgetter("cipher_suite.name"), reverse=True)

        # Generate the results
        return CipherSuitesScanResult(
            tls_version_used=cls._tls_version,
            cipher_suite_preferred_by_server=None,  # TODO
            accepted_cipher_suites=accepted_cipher_suites,
            rejected_cipher_suites=rejected_cipher_suites,
        )


class Sslv20ScanImplementation(_CipherSuitesScanImplementation):
    cli_connector_cls = _Sslv20CliConnector
    _tls_version = OpenSslVersionEnum.SSLV2


class Sslv30ScanImplementation(_CipherSuitesScanImplementation):
    cli_connector_cls = _Sslv30CliConnector
    _tls_version = OpenSslVersionEnum.SSLV3


class Tlsv10ScanImplementation(_CipherSuitesScanImplementation):
    cli_connector_cls = _Tlsv10CliConnector
    _tls_version = OpenSslVersionEnum.TLSV1


class Tlsv11ScanImplementation(_CipherSuitesScanImplementation):
    cli_connector_cls = _Tlsv11CliConnector
    _tls_version = OpenSslVersionEnum.TLSV1_1


class Tlsv12ScanImplementation(_CipherSuitesScanImplementation):
    cli_connector_cls = _Tlsv12CliConnector
    _tls_version = OpenSslVersionEnum.TLSV1_2


class Tlsv13ScanImplementation(_CipherSuitesScanImplementation):
    cli_connector_cls = _Tlsv13CliConnector
    _tls_version = OpenSslVersionEnum.TLSV1_3
