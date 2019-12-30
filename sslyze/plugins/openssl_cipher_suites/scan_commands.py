from abc import abstractmethod
from concurrent.futures import Future
from operator import attrgetter

from dataclasses import dataclass
from nassl.ssl_client import OpenSslVersionEnum

from sslyze.plugins.openssl_cipher_suites.cipher_suites import CipherSuiteScanResult, CipherSuiteScanResultEnum
from sslyze.plugins.openssl_cipher_suites.test_cipher_suite import test_cipher_suite
from sslyze.plugins.plugin_base import ScanCommandImplementation, ScanCommandResult, ScanJob, \
    ScanCommandExtraArguments
from typing import ClassVar, Set, Optional
from typing import List

from sslyze.server_connectivity_tester import ServerConnectivityInfo


@dataclass(frozen=True)
class CipherSuitesExtraArguments(ScanCommandExtraArguments):
    should_send_request_after_tls_handshake: bool


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

    preferred_cipher: Optional[CipherSuiteScanResult]

    accepted_ciphers: List[CipherSuiteScanResult]
    rejected_ciphers: List[CipherSuiteScanResult]
    errored_ciphers: List[CipherSuiteScanResult]


class _CipherSuitesScanImplementation(ScanCommandImplementation):

    # The SSL version corresponding to the scan command
    _ssl_version: ClassVar[OpenSslVersionEnum]

    @classmethod
    @abstractmethod
    def _ciphers_to_scan_for(self, server_info: ServerConnectivityInfo) -> Set[str]:
        pass

    @classmethod
    def scan_jobs_for_scan_command(
            cls,
            server_info: ServerConnectivityInfo,
            extra_arguments: Optional[CipherSuitesExtraArguments] = None
    ) -> List[ScanJob]:
        # Get the list of available cipher suites for the given ssl version
        cipher_list = cls._ciphers_to_scan_for(server_info)
        should_send_request_after_tls_handshake = extra_arguments.should_send_request_after_tls_handshake if extra_arguments else False

        # Run one job per cipher suite to test for
        scan_jobs = [
            ScanJob(
                function_to_call=test_cipher_suite,
                function_arguments=[
                    server_info,
                    cls._ssl_version,
                    cipher,
                    should_send_request_after_tls_handshake
                ]
            ) for cipher in cipher_list
        ]
        return scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
        accepted_cipher_list = []
        rejected_cipher_list = []
        errored_cipher_list = []

        # Store the results as they come
        for completed_job in completed_scan_jobs:
            try:
                cipher_result: CipherSuiteScanResult = completed_job.result()
            except Exception:
                raise
            if cipher_result.result == CipherSuiteScanResultEnum.ACCEPTED_BY_SERVER:
                accepted_cipher_list.append(cipher_result)
            elif cipher_result.result == CipherSuiteScanResultEnum.REJECTED_BY_SERVER:
                rejected_cipher_list.append(cipher_result)
            elif cipher_result.result == CipherSuiteScanResultEnum.UNKNOWN_ERROR:
                errored_cipher_list.append(cipher_result)

        # Sort all the lists
        accepted_cipher_list.sort(key=attrgetter("name"), reverse=True)
        rejected_cipher_list.sort(key=attrgetter("name"), reverse=True)
        errored_cipher_list.sort(key=attrgetter("name"), reverse=True)

        # Generate the results
        plugin_result = CipherSuitesScanResult(
            None,  # TODO: preferred
            accepted_cipher_list,
            rejected_cipher_list,
            errored_cipher_list,
        )
        return plugin_result


class _SimpleCipherSuitesScanImplementation(_CipherSuitesScanImplementation):
    """"From SSL 2.0 to TLS 1.1, the implementation is identical and defined here.
    """

    @classmethod
    def _ciphers_to_scan_for(cls, server_info: ServerConnectivityInfo) -> Set[str]:
        # Simple case for SSL 2 to TLS 1.1
        ssl_connection = server_info.get_preconfigured_ssl_connection(override_tls_version=cls._ssl_version)
        # Disable SRP and PSK cipher suites as they need a special setup in the client and are never used
        ssl_connection.ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
        # And remove TLS 1.3 cipher suites
        return {cipher for cipher in ssl_connection.ssl_client.get_cipher_list() if "TLS13" not in cipher}


class Sslv20ScanImplementation(_SimpleCipherSuitesScanImplementation):
    _ssl_version = OpenSslVersionEnum.SSLV2


class Sslv30ScanImplementation(_SimpleCipherSuitesScanImplementation):
    _ssl_version = OpenSslVersionEnum.SSLV3


class Tlsv10ScanImplementation(_SimpleCipherSuitesScanImplementation):
    _ssl_version = OpenSslVersionEnum.TLSV1


class Tlsv11ScanImplementation(_SimpleCipherSuitesScanImplementation):
    _ssl_version = OpenSslVersionEnum.TLSV1_1


class Tlsv12ScanImplementation(_CipherSuitesScanImplementation):
    """The implementation for TLS 1.2 is customized because some ciphers are supported by different versions of OpenSSL.
    """
    _ssl_version = OpenSslVersionEnum.TLSV1_2

    @classmethod
    def _ciphers_to_scan_for(cls, server_info: ServerConnectivityInfo) -> Set[str]:
        cipher_list: List[str] = []

        # For TLS 1.2, we have to use both the legacy and modern OpenSSL to cover all cipher suites
        ssl_connection_legacy = server_info.get_preconfigured_ssl_connection(
            override_tls_version=cls._ssl_version, should_use_legacy_openssl=True
        )
        ssl_connection_legacy.ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
        cipher_list.extend(ssl_connection_legacy.ssl_client.get_cipher_list())

        ssl_connection_modern = server_info.get_preconfigured_ssl_connection(
            override_tls_version=cls._ssl_version, should_use_legacy_openssl=False
        )
        # Disable the TLS 1.3 cipher suites with the new OpenSSL API
        ssl_connection_modern.ssl_client.set_ciphersuites("")
        # Enable all other cipher suites
        ssl_connection_modern.ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
        cipher_list.extend(ssl_connection_modern.ssl_client.get_cipher_list())

        # And remove duplicates (ie. supported by both legacy and modern OpenSSL)
        return set(cipher_list)


class Tlsv13ScanImplementation(_CipherSuitesScanImplementation):
    _ssl_version = OpenSslVersionEnum.TLSV1_3

    @classmethod
    def _ciphers_to_scan_for(cls, server_info: ServerConnectivityInfo) -> Set[str]:
        # TLS 1.3 only has 5 cipher suites so we can hardcode them
        return {
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_128_CCM_8_SHA256",
            "TLS_AES_128_CCM_SHA256",
        }
