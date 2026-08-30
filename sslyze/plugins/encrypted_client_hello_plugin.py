from dataclasses import dataclass

import dns.exception
import dns.rdatatype
import dns.resolver
from dns.rdtypes.svcbbase import ParamKey, SVCBBase
from nassl.base_ssl_client import ClientCertificateRequested, TlsVersionEnum
from nassl.ech_status_enum import OpenSslEchStatusEnum
from nassl.errors import OpenSSLError
from nassl.openssl_4_0_0.ssl_client import SslClient_OpenSSL_4_0_0

from sslyze.connection_helpers.tls_connection import OpenSslVersionEnum
from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.json.pydantic_utils import Base64StrFromBytes, BaseModelWithOrmModeAndForbid
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
from sslyze.server_connectivity import ServerConnectivityInfo

# The DNS lookup for the server's HTTPS/SVCB record should be fast; don't let it stall a scan for too long
_DNS_LOOKUP_TIMEOUT = 5

# ECH statuses that indicate the server was able to decrypt and process the ECH-protected (inner) ClientHello
_ECH_SUCCESS_STATUSES = (OpenSslEchStatusEnum.SUCCESS, OpenSslEchStatusEnum.BAD_NAME)

# ECH statuses returned when the server rejected the ECHConfigList but supplied a fresh one to retry with
_ECH_RETRYABLE_STATUSES = (OpenSslEchStatusEnum.FAILED_ECH, OpenSslEchStatusEnum.FAILED_ECH_BAD_NAME)


@dataclass(frozen=True)
class EncryptedClientHelloScanResult(ScanCommandResult):
    """The result of testing a server for Encrypted Client Hello (ECH) support.

    Attributes:
        ech_config_list_from_dns: The raw ECHConfigList bytes published in the server's DNS HTTPS/SVCB record's
            "ech" SvcParam, or None if the server's DNS record does not advertise ECH.
        is_real_ech_supported: True if the server genuinely supports ECH: sslyze completed a TLS handshake using the
            server's own published ECHConfigList and the inner (encrypted) ClientHello was decrypted and processed
            by the server. False if the server publishes an ECHConfigList but it does not lead to a working ECH
            handshake, ie. a decoy/placeholder configuration. None if the server's DNS record does not advertise
            ECH, so real ECH support could not be tested.
        ech_inner_sni: The SNI value that was protected/encrypted by ECH, when is_real_ech_supported is True.
        ech_outer_sni: The SNI value that remained visible in cleartext, when is_real_ech_supported is True.
        is_grease_ech_supported: True if the server responded to a GREASE (decoy) Encrypted Client Hello with a set of
            ECH retry configs, which indicates that the server implements ECH at the TLS protocol level, even when
            it does not (yet) advertise a working ECHConfigList via DNS.
        is_ech_config_malformed: True if the server's DNS record publishes an ECHConfigList that could not even be
            parsed (invalid encoding, unknown/bad KEM or version, etc.), which usually points to a misconfigured DNS
            entry rather than a deliberate decoy/placeholder configuration.
    """

    ech_config_list_from_dns: bytes | None
    is_real_ech_supported: bool | None
    ech_inner_sni: str | None
    ech_outer_sni: str | None
    is_grease_ech_supported: bool
    is_ech_config_malformed: bool


class EncryptedClientHelloScanResultAsJson(BaseModelWithOrmModeAndForbid):
    ech_config_list_from_dns: Base64StrFromBytes | None
    is_real_ech_supported: bool | None
    ech_inner_sni: str | None
    ech_outer_sni: str | None
    is_grease_ech_supported: bool
    is_ech_config_malformed: bool


assert EncryptedClientHelloScanResult.__doc__
EncryptedClientHelloScanResultAsJson.__doc__ = EncryptedClientHelloScanResult.__doc__


class EncryptedClientHelloScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: EncryptedClientHelloScanResultAsJson | None


class _EncryptedClientHelloCliConnector(ScanCommandCliConnector[EncryptedClientHelloScanResult, None]):
    _cli_option = "ech"
    _cli_description = "Test a server for Encrypted Client Hello (ECH) support."

    @classmethod
    def result_to_console_output(cls, result: EncryptedClientHelloScanResult) -> list[str]:
        result_as_txt = [cls._format_title("Encrypted Client Hello (ECH)")]

        if result.ech_config_list_from_dns is None:
            result_as_txt.append(
                cls._format_field("", "Server does not publish an ECHConfigList via DNS (HTTPS/SVCB record).")
            )
        elif result.is_real_ech_supported:
            result_as_txt.append(cls._format_field("", "OK - Server supports ECH using its published ECHConfigList."))
            result_as_txt.append(cls._format_field("Inner (protected) SNI:", str(result.ech_inner_sni)))
            result_as_txt.append(cls._format_field("Outer (cleartext) SNI:", str(result.ech_outer_sni)))
        elif result.is_ech_config_malformed:
            result_as_txt.append(
                cls._format_field(
                    "",
                    "MISCONFIGURED - The ECHConfigList published in the server's DNS record could not be parsed"
                    " (invalid encoding); check the HTTPS/SVCB record for a DNS misconfiguration.",
                )
            )
        else:
            result_as_txt.append(
                cls._format_field(
                    "",
                    "Server publishes an ECHConfigList via DNS but it did NOT lead to a working ECH handshake"
                    " (likely a decoy/GREASE-only configuration).",
                )
            )

        result_as_txt.append(
            cls._format_field(
                "Responds to GREASE ECH:",
                "Yes - server implements ECH at the protocol level" if result.is_grease_ech_supported else "No",
            )
        )
        return result_as_txt


class EncryptedClientHelloImplementation(ScanCommandImplementation[EncryptedClientHelloScanResult, None]):
    """Test a server for Encrypted Client Hello (ECH) support."""

    cli_connector_cls = _EncryptedClientHelloCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: ScanCommandExtraArgument | None = None
    ) -> list[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        if server_info.tls_probing_result.highest_tls_version_supported.value < TlsVersionEnum.TLS_1_3.value:
            # ECH requires TLS 1.3
            return []

        return [
            ScanJob(function_to_call=_test_real_ech, function_arguments=[server_info]),
            ScanJob(function_to_call=_test_grease_ech, function_arguments=[server_info]),
        ]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: list[ScanJobResult]
    ) -> EncryptedClientHelloScanResult:
        if server_info.tls_probing_result.highest_tls_version_supported.value < TlsVersionEnum.TLS_1_3.value:
            # TLS 1.3 was not supported so no jobs were queued
            assert not scan_job_results
            return EncryptedClientHelloScanResult(
                ech_config_list_from_dns=None,
                is_real_ech_supported=None,
                ech_inner_sni=None,
                ech_outer_sni=None,
                is_grease_ech_supported=False,
                is_ech_config_malformed=False,
            )

        # Process the actual results
        assert len(scan_job_results) == 2, f"Unexpected number of scan jobs received: {scan_job_results}"
        real_ech_result: _RealEchTestResult | None = None
        grease_ech_result: _GreaseEchTestResult | None = None
        for job_result in scan_job_results:
            result_value = job_result.get_result()
            if isinstance(result_value, _RealEchTestResult):
                real_ech_result = result_value
            elif isinstance(result_value, _GreaseEchTestResult):
                grease_ech_result = result_value
        assert real_ech_result is not None, "Should never happen"
        assert grease_ech_result is not None, "Should never happen"

        return EncryptedClientHelloScanResult(
            ech_config_list_from_dns=real_ech_result.ech_config_list,
            is_real_ech_supported=real_ech_result.is_real_ech_supported,
            ech_inner_sni=real_ech_result.inner_sni,
            ech_outer_sni=real_ech_result.outer_sni,
            is_grease_ech_supported=grease_ech_result.is_grease_ech_supported,
            is_ech_config_malformed=real_ech_result.is_ech_config_malformed,
        )


@dataclass(frozen=True)
class _RealEchTestResult:
    ech_config_list: bytes | None
    is_real_ech_supported: bool | None
    inner_sni: str | None
    outer_sni: str | None
    is_ech_config_malformed: bool


@dataclass(frozen=True)
class _GreaseEchTestResult:
    is_grease_ech_supported: bool


def _fetch_ech_config_list_from_dns(hostname: str) -> bytes | None:
    """Look up the target's DNS HTTPS record and extract the raw ECHConfigList from its "ech" SvcParam, if any."""
    try:
        answer = dns.resolver.resolve(hostname, dns.rdatatype.HTTPS, lifetime=_DNS_LOOKUP_TIMEOUT)
    except dns.exception.DNSException:
        return None

    for rdata in answer:
        if not isinstance(rdata, SVCBBase):
            continue
        ech_param = rdata.params.get(ParamKey.ECH)
        if ech_param is not None:
            return ech_param.ech  # type: ignore[attr-defined]

    return None


def _do_ech_handshake(
    server_info: ServerConnectivityInfo, ech_config_list: bytes
) -> tuple[OpenSslEchStatusEnum, str | None, str | None, bytes | None, bool]:
    """Returns (status, inner_sni, outer_sni, retry_config, is_ech_config_malformed)."""
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=TlsVersionEnum.TLS_1_3,
        openssl_version=OpenSslVersionEnum.OPENSSL_4_0_0,
    )
    assert isinstance(ssl_connection.ssl_client, SslClient_OpenSSL_4_0_0), "Should never happen"

    # Set the ECH config
    try:
        # The ECHConfigList comes from DNS and may be malformed (bad KEM/version/zero-length entry, etc.), which
        # usually means the server's DNS entry is misconfigured rather than ECH not being genuinely supported
        ssl_connection.ssl_client.set_ech_config(ech_config_list)
    except OpenSSLError:
        return OpenSslEchStatusEnum.FAILED, None, None, None, True

    # Try to connect
    try:
        ssl_connection.connect()

    except ClientCertificateRequested:
        status, inner_sni, outer_sni = ssl_connection.ssl_client.get_ech_status()
        retry_config = ssl_connection.ssl_client.get_ech_retry_config()

    except (ServerRejectedTlsHandshake, TlsHandshakeTimedOut, OpenSSLError):
        return OpenSslEchStatusEnum.FAILED, None, None, None, False

    else:
        status, inner_sni, outer_sni = ssl_connection.ssl_client.get_ech_status()
        retry_config = ssl_connection.ssl_client.get_ech_retry_config()

    finally:
        ssl_connection.close()

    return status, inner_sni, outer_sni, retry_config, False


def _test_real_ech(server_info: ServerConnectivityInfo) -> _RealEchTestResult:
    ech_config_list = _fetch_ech_config_list_from_dns(server_info.server_location.hostname)
    if ech_config_list is None:
        return _RealEchTestResult(
            ech_config_list=None,
            is_real_ech_supported=None,
            inner_sni=None,
            outer_sni=None,
            is_ech_config_malformed=False,
        )

    status, inner_sni, outer_sni, retry_config, is_ech_config_malformed = _do_ech_handshake(
        server_info, ech_config_list
    )

    if status in _ECH_RETRYABLE_STATUSES and retry_config:
        # The published ECHConfigList was rejected but the server supplied a fresh one to retry with; a real ECH
        # client would retry once, so do the same to avoid a false negative because of a stale DNS cache
        status, inner_sni, outer_sni, _, _ = _do_ech_handshake(server_info, retry_config)

    return _RealEchTestResult(
        ech_config_list=ech_config_list,
        is_real_ech_supported=status in _ECH_SUCCESS_STATUSES,
        inner_sni=inner_sni,
        outer_sni=outer_sni,
        is_ech_config_malformed=is_ech_config_malformed,
    )


def _test_grease_ech(server_info: ServerConnectivityInfo) -> _GreaseEchTestResult:
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=TlsVersionEnum.TLS_1_3,
        openssl_version=OpenSslVersionEnum.OPENSSL_4_0_0,
    )
    assert isinstance(ssl_connection.ssl_client, SslClient_OpenSSL_4_0_0), "Should never happen"
    ssl_connection.ssl_client.enable_ech_grease()

    try:
        ssl_connection.connect()
    except ClientCertificateRequested:
        status, _, _ = ssl_connection.ssl_client.get_ech_status()
    except (ServerRejectedTlsHandshake, TlsHandshakeTimedOut, OpenSSLError):
        status = OpenSslEchStatusEnum.FAILED
    else:
        status, _, _ = ssl_connection.ssl_client.get_ech_status()
    finally:
        ssl_connection.close()

    # GREASE_ECH means the server replied with real ECH retry configs in response to our decoy ClientHello, which
    # only happens if the server actually implements ECH at the protocol level
    return _GreaseEchTestResult(is_grease_ech_supported=status == OpenSslEchStatusEnum.GREASE_ECH)
