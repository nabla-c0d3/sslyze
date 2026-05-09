from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


from nassl.base_ssl_client import ClientCertificateRequested
from nassl.openssl_4_0_0.ssl_client import SslClient_OpenSSL_4_0_0

from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandCliConnector,
    ScanCommandImplementation,
    ScanCommandExtraArgument,
    ScanJob,
    ScanCommandWrongUsageError,
    ScanJobResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


class PqGroup(str, Enum):
    """An ML-KEM hybrid key exchange group that can be offered in TLS 1.3."""

    X25519MLKEM768 = "X25519MLKEM768"
    SECP256R1MLKEM768 = "SecP256r1MLKEM768"
    SECP384R1MLKEM1024 = "SecP384r1MLKEM1024"


@dataclass(frozen=True)
class PqKeyExchangeScanResult(ScanCommandResult):
    """The result of testing a server for Post-Quantum/Hybrid key exchange group support in TLS 1.3.

    Attributes:
        supported_pq_groups: The list of ML-KEM hybrid groups accepted by the server, or None if the
                server does not support TLS 1.3 (PQ groups require TLS 1.3). An empty list means TLS 1.3 is supported but no PQ hybrid groups were accepted.
        supports_pq_key_exchange: True if the server accepted at least one PQ/hybrid group.
    """

    supported_pq_groups: Optional[List[str]]
    supports_pq_key_exchange: bool

    def __post_init__(self) -> None:
        # Sort the groups by name
        if self.supported_pq_groups:
            self.supported_pq_groups.sort()


class PqKeyExchangeScanResultAsJson(BaseModelWithOrmModeAndForbid):
    supported_pq_groups: Optional[List[str]]
    supports_pq_key_exchange: bool


assert PqKeyExchangeScanResult.__doc__
PqKeyExchangeScanResultAsJson.__doc__ = PqKeyExchangeScanResult.__doc__


class PqKeyExchangeScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[PqKeyExchangeScanResultAsJson]


class _PqKeyExchangeCliConnector(ScanCommandCliConnector[PqKeyExchangeScanResult, None]):
    _cli_option = "pq_key_exchange"
    _cli_description = "Test a server for Post-Quantum/Hybrid key exchange group support (requires TLS 1.3)."

    @classmethod
    def result_to_console_output(cls, result: PqKeyExchangeScanResult) -> List[str]:
        result_as_txt = [cls._format_title("Post-Quantum Key Exchange (ML-KEM Hybrid Groups)")]

        if result.supported_pq_groups is None:
            result_as_txt.append(
                cls._format_subtitle("TLS 1.3 is not supported; PQ key exchange testing requires TLS 1.3.")
            )
        elif result.supports_pq_key_exchange:
            result_as_txt.append(cls._format_field("Supported PQ groups:", ", ".join(result.supported_pq_groups)))
        else:
            result_as_txt.append(
                cls._format_subtitle(
                    "VULNERABLE - Server does not support any PQ/hybrid key exchange groups."
                    " It is not protected against 'harvest now, decrypt later' attacks."
                )
            )
        return result_as_txt


class PqKeyExchangeImplementation(ScanCommandImplementation[PqKeyExchangeScanResult, None]):
    """Test a server for Post-Quantum/Hybrid key exchange group support in TLS 1.3."""

    cli_connector_cls = _PqKeyExchangeCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        if server_info.tls_probing_result.highest_tls_version_supported.value < TlsVersionEnum.TLS_1_3.value:
            # Nothing to test: the server doesn't support TLS 1.3
            return [ScanJob(function_to_call=_raise_tls13_not_supported, function_arguments=[])]

        return [ScanJob(function_to_call=_test_pq_group, function_arguments=[server_info, group]) for group in PqGroup]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> PqKeyExchangeScanResult:
        if len(scan_job_results) < 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        if len(scan_job_results) == 1:
            try:
                scan_job_results[0].get_result()
                raise RuntimeError("Should never happen")
            except _Tls13NotSupported:
                return PqKeyExchangeScanResult(
                    supported_pq_groups=None,
                    supports_pq_key_exchange=False,
                )

        all_results = [job.get_result() for job in scan_job_results]
        supported = [r.group.value for r in all_results if r.was_accepted_by_server]
        return PqKeyExchangeScanResult(
            supported_pq_groups=supported,
            supports_pq_key_exchange=bool(supported),
        )


class _Tls13NotSupported(Exception):
    pass


def _raise_tls13_not_supported() -> None:
    raise _Tls13NotSupported()


@dataclass(frozen=True)
class _PqGroupResult:
    group: PqGroup
    was_accepted_by_server: bool


def _test_pq_group(server_info: ServerConnectivityInfo, pq_group: PqGroup) -> _PqGroupResult:
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=TlsVersionEnum.TLS_1_3,
        should_use_openssl_4=True,
    )
    if not isinstance(ssl_connection.ssl_client, SslClient_OpenSSL_4_0_0):
        raise RuntimeError(
            "Should never happen: specified should_use_openssl_4=True but didn't get SslClient_OpenSSL_4_0_0"
        )

    ssl_connection.ssl_client.set_groups_list(pq_group.value)

    negotiated_group: Optional[str] = None
    try:
        ssl_connection.connect()
        negotiated_group = ssl_connection.ssl_client.get_group_name()

    except ClientCertificateRequested:
        negotiated_group = ssl_connection.ssl_client.get_group_name()

    except (ServerRejectedTlsHandshake, TlsHandshakeTimedOut):
        negotiated_group = None

    finally:
        ssl_connection.close()

    if negotiated_group and negotiated_group != pq_group.value:
        raise RuntimeError(
            f"Should never happen: negotiated group should be {pq_group.value} but got {negotiated_group}"
        )

    return _PqGroupResult(group=pq_group, was_accepted_by_server=negotiated_group is not None)
