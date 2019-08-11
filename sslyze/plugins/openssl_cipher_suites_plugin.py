import optparse
from abc import ABC, abstractmethod
from concurrent.futures import Future
from operator import attrgetter
from xml.etree.ElementTree import Element

from dataclasses import dataclass, InitVar
from nassl.ssl_client import OpenSslVersionEnum, ClientCertificateRequested
from sslyze.plugins.plugin_base import ScanCommandImplementation, ScanCommandResult, ScanCommand, ScanJob
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SslConnection
from sslyze.utils.ssl_connection import SslHandshakeRejected
from typing import Dict, Type, ClassVar, Set, Generic, TypeVar
from typing import List
from typing import Optional

from sslyze.utils.tls12_workaround import WorkaroundForTls12ForCipherSuites


@dataclass(frozen=True)
class _OpenSslCipherSuitesScanCommand(ScanCommand):
    # TODO: This is not used?
    should_send_request_after_tls_handshake: bool = False


@dataclass(frozen=True)
class Sslv20ScanCommand(_OpenSslCipherSuitesScanCommand):
    """List the SSL 2.0 OpenSSL cipher suites supported by the server(s).
    """


@dataclass(frozen=True)
class Sslv30ScanCommand(_OpenSslCipherSuitesScanCommand):
    """List the SSL 3.0 OpenSSL cipher suites supported by the server(s).
    """


@dataclass(frozen=True)
class Tlsv10ScanCommand(_OpenSslCipherSuitesScanCommand):
    """List the TLS 1.0 OpenSSL cipher suites supported by the server(s).
    """


@dataclass(frozen=True)
class Tlsv11ScanCommand(_OpenSslCipherSuitesScanCommand):
    """List the TLS 1.1 OpenSSL cipher suites supported by the server(s).
    """


@dataclass(frozen=True)
class Tlsv12ScanCommand(_OpenSslCipherSuitesScanCommand):
    """List the TLS 1.2 OpenSSL cipher suites supported by the server(s).
    """


@dataclass(frozen=True)
class Tlsv13ScanCommand(_OpenSslCipherSuitesScanCommand):
    """List the TLS 1.3 OpenSSL cipher suites supported by the server(s).
    """


# TODO: Forward CLI-only arguments here at the very end
class CliConnector:

    CLI_OPTION_FOR_SCAN_CMD = {
        Tlsv13ScanCommand: "tlsv1_3",
        Tlsv12ScanCommand: "tlsv1_2",
        Tlsv11ScanCommand: "tlsv1_1",
        Tlsv10ScanCommand: "tlsv1_0",
        Sslv30ScanCommand: "sslv3",
        Sslv20ScanCommand: "sslv2",
    }

    ACCEPTED_CIPHER_LINE_FORMAT = "        {cipher_name:<50}{dh_size:<15}{key_size:<10}    {status:<60}"
    REJECTED_CIPHER_LINE_FORMAT = "        {cipher_name:<50}{error_message:<60}"

    def __init__(self, hide_rejected_ciphers: bool):
        self.hide_rejected_ciphers = hide_rejected_ciphers

    # Common formatting methods to have a consistent console output
    @classmethod
    def _format_title(cls, scan_command: _OpenSslCipherSuitesScanCommand) -> str:
        return f" * {cls.CLI_OPTION_FOR_SCAN_CMD[scan_command.__class__].upper()} Cipher Suites:"

    @staticmethod
    def _format_subtitle(subtitle: str) -> str:
        return "     {0}".format(subtitle)

    @staticmethod
    def _format_field(title: str, value: str) -> str:
        return "       {0:<35}{1}".format(title, value)

    def print_result(self, result: "CipherSuiteScanResult") -> List[str]:
        result_txt = [self._format_title(result.scan_command)]

        # If we were able to connect, add some general comments about the cipher suite configuration
        if result.accepted_ciphers:
            supports_forward_secrecy = False

            # All TLS 1.3 cipher suites support forward secrecy
            if isinstance(result.scan_command, Tlsv13ScanCommand):
                supports_forward_secrecy = True
            else:
                for accepted_cipher in result.accepted_ciphers:
                    if "_DHE_" in accepted_cipher.name or "_ECDHE_" in accepted_cipher.name:
                        supports_forward_secrecy = True
                        break

            result_txt.append(
                self._format_field(
                    "Forward Secrecy", "OK - Supported" if supports_forward_secrecy else "INSECURE - Not Supported"
                )
            )

            supports_rc4 = False
            for accepted_cipher in result.accepted_ciphers:
                if "_RC4_" in accepted_cipher.name:
                    supports_rc4 = True
                    break
            result_txt.append(
                self._format_field("RC4", "INSECURE - Supported" if supports_rc4 else "OK - Not Supported")
            )
            result_txt.append("")

        # Output all the accepted ciphers if any
        if len(result.accepted_ciphers) > 0:
            # Start with the preferred cipher
            result_txt.append(self._format_subtitle("Preferred:"))
            if result.preferred_cipher:
                result_txt.append(self._format_accepted_cipher_txt(result.preferred_cipher))
            else:
                result_txt.append(
                    self.REJECTED_CIPHER_LINE_FORMAT.format(
                        cipher_name="None - Server followed client cipher suite preference.", error_message=""
                    )
                )

            # Then display all ciphers that were accepted
            result_txt.append(self._format_subtitle("Accepted:"))
            for accepted_cipher in result.accepted_ciphers:
                result_txt.append(self._format_accepted_cipher_txt(accepted_cipher))
        elif result.scan_command.hide_rejected_ciphers:  # type: ignore
            result_txt.append("      Server rejected all cipher suites.")

        # Output all errors if any
        if len(result.errored_ciphers) > 0:
            result_txt.append(self._format_subtitle("Undefined - An unexpected error happened:"))
            for err_cipher in result.errored_ciphers:
                cipher_line_txt = self.REJECTED_CIPHER_LINE_FORMAT.format(
                    cipher_name=err_cipher.name, error_message=err_cipher.error_message
                )
                result_txt.append(cipher_line_txt)

        # Output all rejected ciphers if needed
        if len(result.rejected_ciphers) > 0 and not self.hide_rejected_ciphers:
            result_txt.append(self._format_subtitle("Rejected:"))
            for rejected_cipher in result.rejected_ciphers:
                cipher_line_txt = self.REJECTED_CIPHER_LINE_FORMAT.format(
                    cipher_name=rejected_cipher.name, error_message=rejected_cipher.handshake_error_message
                )
                result_txt.append(cipher_line_txt)

        return result_txt

    def _format_accepted_cipher_txt(self, cipher: "AcceptedCipherSuite") -> str:
        keysize_str = "{} bits".format(cipher.key_size) if cipher.key_size is not None else ""
        if cipher.is_anonymous:
            # Always display ANON as the key size for anonymous ciphers to make it visible
            keysize_str = "ANONYMOUS"

        cipher_line_txt = self.ACCEPTED_CIPHER_LINE_FORMAT.format(
            cipher_name=cipher.name,
            dh_size="",
            key_size=keysize_str,
            status=cipher.post_handshake_response if cipher.post_handshake_response is not None else "",
        )
        return cipher_line_txt


_ScanCommandTypeVar = TypeVar("_ScanCommandTypeVar", bound=_OpenSslCipherSuitesScanCommand)


class _OpenSslCipherSuitesImplementation(ScanCommandImplementation, Generic[_ScanCommandTypeVar]):
    # The SSL version corresponding to the scan command
    _ssl_version: ClassVar[OpenSslVersionEnum]

    @abstractmethod
    def _ciphers_to_scan_for(self, server_info: ServerConnectivityInfo) -> Set[str]:
        pass

    def scan_jobs_for_scan_command(self, scan_command: _ScanCommandTypeVar) -> List[ScanJob]:
        # Get the list of available cipher suites for the given ssl version
        cipher_list = self._ciphers_to_scan_for(scan_command.server_info)

        # Run one job per cipher suite to test for
        scan_jobs = [
            ScanJob(
                spawned_by_scan_command=scan_command,
                function_to_call=self._test_cipher_suite,
                function_arguments=[scan_command.server_info, self._ssl_version, cipher]
            ) for cipher in cipher_list
        ]
        return scan_jobs

    def result_for_completed_scan_jobs(
        self,
        scan_command: _ScanCommandTypeVar,
        completed_scan_jobs: List[Future]
    ) -> ScanCommandResult[_ScanCommandTypeVar]:
        accepted_cipher_list = []
        rejected_cipher_list = []
        errored_cipher_list = []

        # Store the results as they come
        for completed_job in completed_scan_jobs:
            try:
                cipher_result = completed_job.result()
            except Exception:
                raise

            if isinstance(cipher_result, AcceptedCipherSuite):
                accepted_cipher_list.append(cipher_result)
            elif isinstance(cipher_result, RejectedCipherSuite):
                rejected_cipher_list.append(cipher_result)
            elif isinstance(cipher_result, ErroredCipherSuite):
                errored_cipher_list.append(cipher_result)

        # Sort all the lists
        accepted_cipher_list.sort(key=attrgetter("name"), reverse=True)
        rejected_cipher_list.sort(key=attrgetter("name"), reverse=True)
        errored_cipher_list.sort(key=attrgetter("name"), reverse=True)

        # Generate the results
        plugin_result = CipherSuiteScanResult(
            scan_command,
            None,  # TODO: preferred
            accepted_cipher_list,
            rejected_cipher_list,
            errored_cipher_list,
        )
        return plugin_result

    @staticmethod
    def _test_cipher_suite(
        server_connectivity_info: ServerConnectivityInfo, ssl_version: OpenSslVersionEnum, openssl_cipher_name: str
    ) -> "_CipherSuite":
        """Initiates a SSL handshake with the server using the SSL version and the cipher suite specified.
        """
        requires_legacy_openssl = True
        if ssl_version == OpenSslVersionEnum.TLSV1_2:
            # For TLS 1.2, we need to pick the right version of OpenSSL depending on which cipher suite
            requires_legacy_openssl = WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(openssl_cipher_name)
        elif ssl_version == OpenSslVersionEnum.TLSV1_3:
            requires_legacy_openssl = False

        ssl_connection = server_connectivity_info.get_preconfigured_ssl_connection(
            override_ssl_version=ssl_version, should_use_legacy_openssl=requires_legacy_openssl
        )

        # Only enable the cipher suite to test; not trivial anymore since OpenSSL 1.1.1 and TLS 1.3
        if ssl_version == OpenSslVersionEnum.TLSV1_3:
            # The function to control cipher suites is different for TLS 1.3
            # Disable the default, non-TLS 1.3 cipher suites
            ssl_connection.ssl_client.set_cipher_list("")
            # Enable the one TLS 1.3 cipher suite we want to test
            ssl_connection.ssl_client.set_ciphersuites(openssl_cipher_name)
        else:
            if not requires_legacy_openssl:
                # Disable the TLS 1.3 cipher suites if we are using the modern client
                ssl_connection.ssl_client.set_ciphersuites("")

            ssl_connection.ssl_client.set_cipher_list(openssl_cipher_name)

        if len(ssl_connection.ssl_client.get_cipher_list()) != 1:
            raise ValueError(
                f'Passed an OpenSSL string for multiple cipher suites: "{openssl_cipher_name}": '
                f"{str(ssl_connection.ssl_client.get_cipher_list())}"
            )

        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            cipher_result: _CipherSuite = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)

        except SslHandshakeRejected as e:
            cipher_result = RejectedCipherSuite(openssl_cipher_name, ssl_version, str(e))

        except ClientCertificateRequested:
            # TODO(AD): Sometimes get_current_cipher_name() called in from_ongoing_ssl_connection() will return None
            # When the handshake failed due to ClientCertificateRequested
            # We need to rewrite this logic to not use OpenSSL for looking up key size and RFC names as it is
            # too complicated
            # cipher_result = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
            # The ClientCertificateRequested exception already proves that the cipher suite was accepted
            # Workaround here:
            cipher_result = AcceptedCipherSuite(openssl_cipher_name, ssl_version, None, None)

        except Exception as e:
            cipher_result = ErroredCipherSuite(openssl_cipher_name, ssl_version, e)

        finally:
            ssl_connection.close()

        return cipher_result

    @classmethod
    def _get_preferred_cipher_suite(
        cls,
        server_connectivity_info: ServerConnectivityInfo,
        ssl_version: OpenSslVersionEnum,
        accepted_cipher_list: List["AcceptedCipherSuite"],
    ) -> Optional["AcceptedCipherSuite"]:
        """Try to detect the server's preferred cipher suite among all cipher suites supported by SSLyze.
        """
        if len(accepted_cipher_list) < 2:
            return None

        accepted_cipher_names = [cipher.openssl_name for cipher in accepted_cipher_list]
        should_use_legacy_openssl = None

        # For TLS 1.2, we need to figure whether the modern or legacy OpenSSL should be used to connect
        if ssl_version == OpenSslVersionEnum.TLSV1_2:
            should_use_legacy_openssl = True
            # If there are more than two modern-supported cipher suites, use the modern OpenSSL
            for cipher_name in accepted_cipher_names:
                modern_supported_cipher_count = 0
                if not WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(cipher_name):
                    modern_supported_cipher_count += 1

                if modern_supported_cipher_count > 1:
                    should_use_legacy_openssl = False
                    break

        first_cipher_str = ", ".join(accepted_cipher_names)
        # Swap the first two ciphers in the list to see if the server always picks the client's first cipher
        second_cipher_str = ", ".join([accepted_cipher_names[1], accepted_cipher_names[0]] + accepted_cipher_names[2:])

        try:
            first_cipher = cls._get_selected_cipher_suite(
                server_connectivity_info, ssl_version, first_cipher_str, should_use_legacy_openssl
            )
            second_cipher = cls._get_selected_cipher_suite(
                server_connectivity_info, ssl_version, second_cipher_str, should_use_legacy_openssl
            )
        except (SslHandshakeRejected, ConnectionError):
            # Could not complete a handshake
            return None

        if first_cipher.name == second_cipher.name:
            # The server has its own preference for picking a cipher suite
            return first_cipher
        else:
            # The server has no preferred cipher suite as it follows the client's preference for picking a cipher suite
            return None

    @staticmethod
    def _get_selected_cipher_suite(
        server_connectivity: ServerConnectivityInfo,
        ssl_version: OpenSslVersionEnum,
        openssl_cipher_str: str,
        should_use_legacy_openssl: Optional[bool],
    ) -> "AcceptedCipherSuite":
        """Given an OpenSSL cipher string (which may specify multiple cipher suites), return the cipher suite that was
        selected by the server during the SSL handshake.
        """
        ssl_connection = server_connectivity.get_preconfigured_ssl_connection(
            override_ssl_version=ssl_version, should_use_legacy_openssl=should_use_legacy_openssl
        )
        ssl_connection.ssl_client.set_cipher_list(openssl_cipher_str)

        # Perform the SSL handshake
        try:
            ssl_connection.connect()
            selected_cipher = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
        except ClientCertificateRequested:
            selected_cipher = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
        finally:
            ssl_connection.close()
        return selected_cipher


class _SimpleTlsImplementation(_OpenSslCipherSuitesImplementation, Generic[_ScanCommandTypeVar]):
    def _ciphers_to_scan_for(self, server_info: ServerConnectivityInfo) -> Set[str]:
        # Simple case for SSL 2 to TLS 1.1
        ssl_connection = server_info.get_preconfigured_ssl_connection(override_ssl_version=self._ssl_version)
        # Disable SRP and PSK cipher suites as they need a special setup in the client and are never used
        ssl_connection.ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
        # And remove TLS 1.3 cipher suites
        return {cipher for cipher in ssl_connection.ssl_client.get_cipher_list() if "TLS13" not in cipher}


class Sslv20Implementation(_SimpleTlsImplementation[Sslv20ScanCommand]):
    _ssl_version = OpenSslVersionEnum.SSLV2


class Sslv30Implementation(_SimpleTlsImplementation[Sslv30ScanCommand]):
    _ssl_version = OpenSslVersionEnum.SSLV3


class Tlsv10Implementation(_SimpleTlsImplementation[Tlsv10ScanCommand]):
    _ssl_version = OpenSslVersionEnum.TLSV1


class Tlsv11Implementation(_SimpleTlsImplementation[Tlsv11ScanCommand]):
    _ssl_version = OpenSslVersionEnum.TLSV1_1


class Tlsv12Implementation(_OpenSslCipherSuitesImplementation[Tlsv12ScanCommand]):
    _ssl_version = OpenSslVersionEnum.TLSV1_2

    def _ciphers_to_scan_for(self, server_info: ServerConnectivityInfo) -> Set[str]:
        cipher_list: List[str] = []

        # For TLS 1.2, we have to use both the legacy and modern OpenSSL to cover all cipher suites
        ssl_connection_legacy = server_info.get_preconfigured_ssl_connection(
            override_ssl_version=self._ssl_version, should_use_legacy_openssl=True
        )
        ssl_connection_legacy.ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
        cipher_list.extend(ssl_connection_legacy.ssl_client.get_cipher_list())

        ssl_connection_modern = server_info.get_preconfigured_ssl_connection(
            override_ssl_version=self._ssl_version, should_use_legacy_openssl=False
        )
        # Disable the TLS 1.3 cipher suites with the new OpenSSL API
        ssl_connection_modern.ssl_client.set_ciphersuites("")
        # Enable all other cipher suites
        ssl_connection_modern.ssl_client.set_cipher_list("ALL:COMPLEMENTOFALL:-PSK:-SRP")
        cipher_list.extend(ssl_connection_modern.ssl_client.get_cipher_list())

        # And remove duplicates (ie. supported by both legacy and modern OpenSSL)
        return set(cipher_list)


class Tlsv13Implementation(_OpenSslCipherSuitesImplementation[Tlsv13ScanCommand]):
    _ssl_version = OpenSslVersionEnum.TLSV1_3

    def _ciphers_to_scan_for(self, server_info: ServerConnectivityInfo) -> Set[str]:
        # TLS 1.3 only has 5 cipher suites so we can hardcode them
        return {
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_128_CCM_8_SHA256",
            "TLS_AES_128_CCM_SHA256",
        }

# TODO: Auto figure it out with annotations
class Plugin:
    IMPL_FOR_SCAN_CMD = {
        Tlsv13ScanCommand: Tlsv13Implementation,
        Tlsv12ScanCommand: Tlsv12Implementation,
        Tlsv11ScanCommand: Tlsv11Implementation,
        Tlsv10ScanCommand: Tlsv10Implementation,
        Sslv30ScanCommand: Sslv30Implementation,
        Sslv20ScanCommand: Sslv20Implementation,
    }


@dataclass(frozen=True)
class _CipherSuite(ABC):

    openssl_name: str
    ssl_version: OpenSslVersionEnum

    @property
    def name(self) -> str:
        """OpenSSL uses a different naming convention than the corresponding RFCs.
        """
        return OPENSSL_TO_RFC_NAMES_MAPPING[self.ssl_version].get(self.openssl_name, self.openssl_name)

    @property
    def is_anonymous(self):
        return True if "anon" in self.name else False


@dataclass(frozen=True)
class AcceptedCipherSuite(_CipherSuite):
    """An SSL cipher suite the server accepted.

    Attributes:
        name: The cipher suite's RFC name.
        openssl_name: The cipher suite's OpenSSL name.
        ssl_version: The cipher suite's corresponding SSL/TLS version.
        is_anonymous: True if the cipher suite is an anonymous cipher suite (ie. no server authentication).
        key_size: The key size of the cipher suite's algorithm in bits. None if the key size could not be looked up for
            this cipher suite.
        post_handshake_response: The server's response after completing the SSL/TLS handshake and
            sending a request, based on the TlsWrappedProtocolEnum set for this server. For example, this will contain
            an HTTP response when scanning an HTTPS server with TlsWrappedProtocolEnum.HTTPS as the
            tls_wrapped_protocol.
    """
    key_size: int
    post_handshake_response: str

    @classmethod
    def from_ongoing_ssl_connection(
        cls, ssl_connection: SslConnection, ssl_version: OpenSslVersionEnum
    ) -> "AcceptedCipherSuite":
        keysize = ssl_connection.ssl_client.get_current_cipher_bits()
        picked_cipher_name = ssl_connection.ssl_client.get_current_cipher_name()
        status_msg = ssl_connection.post_handshake_check()
        return AcceptedCipherSuite(picked_cipher_name, ssl_version, keysize, status_msg)


@dataclass(frozen=True)
class RejectedCipherSuite(_CipherSuite):
    """An SSL cipher suite the server explicitly rejected.

    Attributes:
        name: The cipher suite's RFC name.
        openssl_name: The cipher suite's OpenSSL name.
        ssl_version: The cipher suite's corresponding SSL/TLS version.
        is_anonymous: True if the cipher suite is an anonymous cipher suite (ie. no server authentication).
        handshake_error_message: The SSL/TLS error returned by the server to close the handshake.
    """
    handshake_error_message: str


@dataclass(frozen=True)
class ErroredCipherSuite(_CipherSuite):
    """An SSL cipher suite that triggered an unexpected error during the SSL handshake with the server.

    Attributes:
        name: The cipher suite's RFC name.
        openssl_name: The cipher suite's OpenSSL name.
        ssl_version: The cipher suite's corresponding SSL/TLS version.
        is_anonymous: True if the cipher suite is an anonymous cipher suite (ie. no server authentication).
        error_message: The text-formatted exception that was raised during the handshake.
    """
    error_message: str

    @classmethod
    def from_exception(cls, openssl_name: str, ssl_version: OpenSslVersionEnum, exception: Exception):
        return cls(
            openssl_name=openssl_name,
            ssl_version=ssl_version,
            error_message=f"{exception.__class__.__name__} - {str(exception)}"
        )


@dataclass(frozen=True)
class CipherSuiteScanResult(ScanCommandResult):
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

    preferred_cipher: Optional[AcceptedCipherSuite]

    accepted_ciphers: List[AcceptedCipherSuite]
    rejected_ciphers: List[RejectedCipherSuite]
    errored_ciphers: List[ErroredCipherSuite]


# Cipher suite name mappings so we can return the RFC names, instead of the OpenSSL names
# Based on https://testssl.sh/openssl-rfc.mappping.html
SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING = {
    "RC4-MD5": "SSL_CK_RC4_128_WITH_MD5",
    "EXP-RC4-MD5": "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
    "RC2-CBC-MD5": "SSL_CK_RC2_128_CBC_WITH_MD5",
    "EXP-RC2-CBC-MD5": "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
    "IDEA-CBC-MD5": "SSL_CK_IDEA_128_CBC_WITH_MD5",
    "DES-CBC-MD5": "SSL_CK_DES_64_CBC_WITH_MD5",
    "DES-CBC3-MD5": "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
    "RC4-64-MD5": "SSL_CK_RC4_64_WITH_MD5",
    "NULL-MD5": "TLS_RSA_WITH_NULL_MD5",
}

TLS_OPENSSL_TO_RFC_NAMES_MAPPING = {
    "NULL-MD5": "TLS_RSA_WITH_NULL_MD5",
    "NULL-SHA": "TLS_RSA_WITH_NULL_SHA",
    "EXP-RC4-MD5": "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "RC4-MD5": "TLS_RSA_WITH_RC4_128_MD5",
    "RC4-SHA": "TLS_RSA_WITH_RC4_128_SHA",
    "EXP-RC2-CBC-MD5": "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    "IDEA-CBC-SHA": "TLS_RSA_WITH_IDEA_CBC_SHA",
    "EXP-DES-CBC-SHA": "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "DES-CBC-SHA": "TLS_RSA_WITH_DES_CBC_SHA",
    "DES-CBC3-SHA": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "EXP-DH-DSS-DES-CBC-SHA": "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "DH-DSS-DES-CBC-SHA": "TLS_DH_DSS_WITH_DES_CBC_SHA",
    "DH-DSS-DES-CBC3-SHA": "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
    "EXP-DH-RSA-DES-CBC-SHA": "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "DH-RSA-DES-CBC-SHA": "TLS_DH_RSA_WITH_DES_CBC_SHA",
    "DH-RSA-DES-CBC3-SHA": "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
    "EXP-EDH-DSS-DES-CBC-SHA": "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    "EDH-DSS-DES-CBC-SHA": "TLS_DHE_DSS_WITH_DES_CBC_SHA",
    "EDH-DSS-DES-CBC3-SHA": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "EXP-EDH-RSA-DES-CBC-SHA": "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "EDH-RSA-DES-CBC-SHA": "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    "EDH-RSA-DES-CBC3-SHA": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "EXP-ADH-RC4-MD5": "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
    "ADH-RC4-MD5": "TLS_DH_anon_WITH_RC4_128_MD5",
    "EXP-ADH-DES-CBC-SHA": "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    "ADH-DES-CBC-SHA": "TLS_DH_anon_WITH_DES_CBC_SHA",
    "ADH-DES-CBC3-SHA": "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "KRB5-DES-CBC-SHA": "TLS_KRB5_WITH_DES_CBC_SHA",
    "KRB5-DES-CBC3-SHA": "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
    "KRB5-RC4-SHA": "TLS_KRB5_WITH_RC4_128_SHA",
    "KRB5-IDEA-CBC-SHA": "TLS_KRB5_WITH_IDEA_CBC_SHA",
    "KRB5-DES-CBC-MD5": "TLS_KRB5_WITH_DES_CBC_MD5",
    "KRB5-DES-CBC3-MD5": "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
    "KRB5-RC4-MD5": "TLS_KRB5_WITH_RC4_128_MD5",
    "KRB5-IDEA-CBC-MD5": "TLS_KRB5_WITH_IDEA_CBC_MD5",
    "EXP-KRB5-DES-CBC-SHA": "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
    "EXP-KRB5-RC2-CBC-SHA": "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
    "EXP-KRB5-RC4-SHA": "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
    "EXP-KRB5-DES-CBC-MD5": "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
    "EXP-KRB5-RC2-CBC-MD5": "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
    "EXP-KRB5-RC4-MD5": "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
    "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "DH-DSS-AES128-SHA": "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
    "DH-RSA-AES128-SHA": "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
    "DHE-DSS-AES128-SHA": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    "DHE-RSA-AES128-SHA": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "ADH-AES128-SHA": "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "DH-DSS-AES256-SHA": "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
    "DH-RSA-AES256-SHA": "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
    "DHE-DSS-AES256-SHA": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    "DHE-RSA-AES256-SHA": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "ADH-AES256-SHA": "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    "NULL-SHA256": "TLS_RSA_WITH_NULL_SHA256",
    "AES128-SHA256": "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "AES256-SHA256": "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "DH-DSS-AES128-SHA256": "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
    "DH-RSA-AES128-SHA256": "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
    "DHE-DSS-AES128-SHA256": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    "CAMELLIA128-SHA": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "DH-DSS-CAMELLIA128-SHA": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
    "DH-RSA-CAMELLIA128-SHA": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "DHE-DSS-CAMELLIA128-SHA": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
    "DHE-RSA-CAMELLIA128-SHA": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "ADH-CAMELLIA128-SHA": "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
    "EXP1024-DES-CBC-SHA": "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
    "EXP1024-DHE-DSS-DES-CBC-SHA": "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
    "EXP1024-RC4-SHA": "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
    "EXP1024-RC4-MD5": "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
    "EXP1024-RC2-CBC-MD5": "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
    "EXP1024-DHE-DSS-RC4-SHA": "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
    "DHE-DSS-RC4-SHA": "TLS_DHE_DSS_WITH_RC4_128_SHA",
    "DHE-RSA-AES128-SHA256": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "DH-DSS-AES256-SHA256": "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
    "DH-RSA-AES256-SHA256": "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
    "DHE-DSS-AES256-SHA256": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    "DHE-RSA-AES256-SHA256": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "ADH-AES128-SHA256": "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    "ADH-AES256-SHA256": "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    "GOST94-GOST89-GOST89": "TLS_GOSTR341094_WITH_28147_CNT_IMIT",
    "GOST2001-GOST89-GOST89": "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
    "CAMELLIA256-SHA": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "DH-DSS-CAMELLIA256-SHA": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
    "DH-RSA-CAMELLIA256-SHA": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "DHE-DSS-CAMELLIA256-SHA": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    "DHE-RSA-CAMELLIA256-SHA": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "ADH-CAMELLIA256-SHA": "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
    "PSK-RC4-SHA": "TLS_PSK_WITH_RC4_128_SHA",
    "PSK-3DES-EDE-CBC-SHA": "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    "PSK-AES128-CBC-SHA": "TLS_PSK_WITH_AES_128_CBC_SHA",
    "PSK-AES256-CBC-SHA": "TLS_PSK_WITH_AES_256_CBC_SHA",
    "RSA-PSK-RC4-SHA": "TLS_RSA_PSK_WITH_RC4_128_SHA",
    "RSA-PSK-3DES-EDE-CBC-SHA": "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
    "RSA-PSK-AES128-CBC-SHA": "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    "RSA-PSK-AES256-CBC-SHA": "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
    "SEED-SHA": "TLS_RSA_WITH_SEED_CBC_SHA",
    "DH-DSS-SEED-SHA": "TLS_DH_DSS_WITH_SEED_CBC_SHA",
    "DH-RSA-SEED-SHA": "TLS_DH_RSA_WITH_SEED_CBC_SHA",
    "DHE-DSS-SEED-SHA": "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
    "DHE-RSA-SEED-SHA": "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    "ADH-SEED-SHA": "TLS_DH_anon_WITH_SEED_CBC_SHA",
    "AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "DHE-RSA-AES128-GCM-SHA256": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "DHE-RSA-AES256-GCM-SHA384": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "DH-RSA-AES128-GCM-SHA256": "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
    "DH-RSA-AES256-GCM-SHA384": "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
    "DHE-DSS-AES128-GCM-SHA256": "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    "DHE-DSS-AES256-GCM-SHA384": "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    "DH-DSS-AES128-GCM-SHA256": "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
    "DH-DSS-AES256-GCM-SHA384": "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
    "ADH-AES128-GCM-SHA256": "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    "ADH-AES256-GCM-SHA384": "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    "CAMELLIA128-SHA256": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "DH-DSS-CAMELLIA128-SHA256": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    "DH-RSA-CAMELLIA128-SHA256": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "DHE-DSS-CAMELLIA128-SHA256": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    "DHE-RSA-CAMELLIA128-SHA256": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ADH-CAMELLIA128-SHA256": "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
    "CAMELLIA256-SHA256": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    "DH-DSS-CAMELLIA256-SHA256": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    "DH-RSA-CAMELLIA256-SHA256": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    "DHE-DSS-CAMELLIA256-SHA256": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    "DHE-RSA-CAMELLIA256-SHA256": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    "ADH-CAMELLIA256-SHA256": "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
    "TLS_FALLBACK_SCSV": "TLS_FALLBACK_SCSV",
    "ECDH-ECDSA-NULL-SHA": "TLS_ECDH_ECDSA_WITH_NULL_SHA",
    "ECDH-ECDSA-RC4-SHA": "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    "ECDH-ECDSA-DES-CBC3-SHA": "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "ECDH-ECDSA-AES128-SHA": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDH-ECDSA-AES256-SHA": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    "ECDHE-ECDSA-NULL-SHA": "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    "ECDHE-ECDSA-RC4-SHA": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "ECDHE-ECDSA-DES-CBC3-SHA": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "ECDH-RSA-NULL-SHA": "TLS_ECDH_RSA_WITH_NULL_SHA",
    "ECDH-RSA-RC4-SHA": "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    "ECDH-RSA-DES-CBC3-SHA": "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    "ECDH-RSA-AES128-SHA": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    "ECDH-RSA-AES256-SHA": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    "ECDHE-RSA-NULL-SHA": "TLS_ECDHE_RSA_WITH_NULL_SHA",
    "ECDHE-RSA-RC4-SHA": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "ECDHE-RSA-DES-CBC3-SHA": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "ECDHE-RSA-AES128-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-AES256-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "AECDH-NULL-SHA": "TLS_ECDH_anon_WITH_NULL_SHA",
    "AECDH-RC4-SHA": "TLS_ECDH_anon_WITH_RC4_128_SHA",
    "AECDH-DES-CBC3-SHA": "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    "AECDH-AES128-SHA": "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    "AECDH-AES256-SHA": "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    "SRP-3DES-EDE-CBC-SHA": "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
    "SRP-RSA-3DES-EDE-CBC-SHA": "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
    "SRP-DSS-3DES-EDE-CBC-SHA": "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
    "SRP-AES-128-CBC-SHA": "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
    "SRP-RSA-AES-128-CBC-SHA": "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
    "SRP-DSS-AES-128-CBC-SHA": "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
    "SRP-AES-256-CBC-SHA": "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
    "SRP-RSA-AES-256-CBC-SHA": "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
    "SRP-DSS-AES-256-CBC-SHA": "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
    "ECDHE-ECDSA-AES128-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-ECDSA-AES256-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "ECDH-ECDSA-AES128-SHA256": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    "ECDH-ECDSA-AES256-SHA384": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    "ECDHE-RSA-AES128-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-RSA-AES256-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "ECDH-RSA-AES128-SHA256": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    "ECDH-RSA-AES256-SHA384": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDH-ECDSA-AES128-GCM-SHA256": "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDH-ECDSA-AES256-GCM-SHA384": "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDH-RSA-AES128-GCM-SHA256": "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    "ECDH-RSA-AES256-GCM-SHA384": "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-CAMELLIA128-SHA256": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDHE-ECDSA-CAMELLIA256-SHA384": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDH-ECDSA-CAMELLIA128-SHA256": "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDH-ECDSA-CAMELLIA256-SHA384": "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDHE-RSA-CAMELLIA128-SHA256": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDHE-RSA-CAMELLIA256-SHA384": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDH-RSA-CAMELLIA128-SHA256": "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDH-RSA-CAMELLIA256-SHA384": "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "DHE-RSA-CHACHA20-POLY1305": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305-OLD": "OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305-OLD": "OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "DHE-RSA-CHACHA20-POLY1305-OLD": "OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "DHE-RSA-DES-CBC3-SHA": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "DHE-DSS-DES-CBC3-SHA": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "AES128-CCM": "RSA_WITH_AES_128_CCM",
    "AES256-CCM": "RSA_WITH_AES_256_CCM",
    "DHE-RSA-AES128-CCM": "DHE_RSA_WITH_AES_128_CCM",
    "DHE-RSA-AES256-CCM": "TLS_DHE_RSA_WITH_AES_256_CCM",
    "AES128-CCM8": "RSA_WITH_AES_128_CCM_8",
    "AES256-CCM8": "RSA_WITH_AES_256_CCM_8",
    "DHE-RSA-AES128-CCM8": "DHE_RSA_WITH_AES_128_CCM_8",
    "DHE-RSA-AES256-CCM8": "DHE_RSA_WITH_AES_256_CCM_8",
    "ECDHE-ECDSA-AES128-CCM": "ECDHE_ECDSA_WITH_AES_128_CCM",
    "ECDHE-ECDSA-AES256-CCM": "ECDHE_ECDSA_WITH_AES_256_CCM",
    "ECDHE-ECDSA-AES128-CCM8": "ECDHE_ECDSA_WITH_AES_128_CCM_8",
    "ECDHE-ECDSA-AES256-CCM8": "ECDHE_ECDSA_WITH_AES_256_CCM_8",
}


OPENSSL_TO_RFC_NAMES_MAPPING: Dict[OpenSslVersionEnum, Dict[str, str]] = {
    OpenSslVersionEnum.SSLV2: SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.SSLV3: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1_1: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1_2: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1_3: {},  # For TLS 1.3, OpenSSL directly uses the RFC names
}
