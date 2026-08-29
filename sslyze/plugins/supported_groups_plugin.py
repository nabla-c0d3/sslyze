from dataclasses import dataclass

from nassl.base_ssl_client import ClientCertificateRequested
from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo, OpenSslGroupNameEnum, OpenSslGroupTypeEnum
from nassl.errors import OpenSSLError
from nassl.openssl_4_0_0.ssl_client import SslClient_OpenSSL_4_0_0
from nassl.tls_version_enum import TlsVersionEnum

from sslyze.connection_helpers.tls_connection import OpenSslVersionEnum
from sslyze.errors import ServerRejectedTlsHandshake, TlsHandshakeTimedOut
from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid
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
from sslyze.server_connectivity import ServerConnectivityInfo, enable_ecdh_cipher_suites


@dataclass(frozen=True)
class SupportedGroupsScanResult(ScanCommandResult):
    """The result of testing a server for Supported Groups.
    Attributes:
        supported_elliptic_curve_groups: A list of Elliptic Curve groups that were accepted by the server, or None
            if the server does not support any cipher suite with an ECDH key exchange.
        rejected_elliptic_curve_groups: A list of Elliptic Curve groups that were rejected by the server, or None
            if the server does not support any cipher suite with an ECDH key exchange.
        supports_elliptic_curve_key_exchange: True if at least one Elliptic Curve group was accepted by the server.
        supported_finite_field_dh_groups: A list of Finite Field DH groups that were accepted by the server.
        rejected_finite_field_dh_groups: A list of Finite Field DH groups that were rejected by the server.
        supported_post_quantum_groups: A list of Post Quantum groups (hybrid and non-hybrid) that were accepted by
            the server, or None if the server does not support TLS 1.3 (PQ groups require TLS 1.3).
        rejected_post_quantum_groups: A list of Post Quantum groups that were rejected by the server, or None if
            the server does not support TLS 1.3 (PQ groups require TLS 1.3).
        supports_post_quantum_key_exchange: True if the server accepted at least one PQ/hybrid group.
    """

    # TLS 1.2 or 1.3
    supported_elliptic_curve_groups: list[str] | None
    rejected_elliptic_curve_groups: list[str] | None
    supports_elliptic_curve_key_exchange: bool

    supported_finite_field_dh_groups: list[str]
    rejected_finite_field_dh_groups: list[str]

    # TLS 1.3 only
    supported_post_quantum_groups: list[str] | None
    rejected_post_quantum_groups: list[str] | None
    supports_post_quantum_key_exchange: bool

    def __post_init__(self) -> None:
        # Sort lists by name so that the output is deterministic
        for attr_name in [
            "supported_elliptic_curve_groups",
            "rejected_elliptic_curve_groups",
            "supported_finite_field_dh_groups",
            "rejected_finite_field_dh_groups",
            "supported_post_quantum_groups",
            "rejected_post_quantum_groups",
        ]:
            attr_value = getattr(self, attr_name)
            if attr_value is not None:
                attr_value.sort()


class SupportedGroupsScanResultAsJson(BaseModelWithOrmModeAndForbid):
    supported_elliptic_curve_groups: list[str] | None
    rejected_elliptic_curve_groups: list[str] | None
    supports_elliptic_curve_key_exchange: bool

    supported_finite_field_dh_groups: list[str]
    rejected_finite_field_dh_groups: list[str]

    supported_post_quantum_groups: list[str] | None
    rejected_post_quantum_groups: list[str] | None
    supports_post_quantum_key_exchange: bool


assert SupportedGroupsScanResult.__doc__
SupportedGroupsScanResultAsJson.__doc__ = SupportedGroupsScanResult.__doc__


class SupportedGroupsScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: SupportedGroupsScanResultAsJson | None


class _SupportedGroupsCliConnector(ScanCommandCliConnector[SupportedGroupsScanResult, None]):
    _cli_option = "supported_groups"
    _cli_description = (
        "Test a server for Supported Groups, including Post-Quantum/Hybrid key exchange and Elliptic Curve groups."
    )

    @staticmethod
    def _groups_to_text(groups: list[str]) -> str:
        return ", ".join(groups) if groups else "None"

    @classmethod
    def result_to_console_output(cls, result: SupportedGroupsScanResult) -> list[str]:
        result_as_txt = [cls._format_title("Supported Groups")]

        # Output for PQ groups
        if result.supported_post_quantum_groups is None:
            result_as_txt.append(
                cls._format_field(
                    "Post-Quantum Key Exchange:",
                    "VULNERABLE - TLS 1.3 is not supported but Post-Quantum/hybrid key exchange requires TLS 1.3. Server is NOT protected against 'harvest now, decrypt later' attacks.",
                )
            )
        elif not result.supported_post_quantum_groups:
            result_as_txt.append(
                cls._format_field(
                    "Post-Quantum Key Exchange:",
                    "VULNERABLE - Server does not support any Post-Quantum/hybrid key exchange groups. It is NOT protected against 'harvest now, decrypt later' attacks.",
                )
            )
            assert result.rejected_post_quantum_groups is not None, "Should never happen"
            result_as_txt.append(
                cls._format_field(
                    "Rejected Post-Quantum groups:", cls._groups_to_text(result.rejected_post_quantum_groups)
                )
            )
        else:
            result_as_txt.append(
                cls._format_field(
                    "Post-Quantum Key Exchange:",
                    "OK - Server supports at least one Post-Quantum/hybrid key exchange group. It is protected against 'harvest now, decrypt later' attacks.",
                )
            )
            result_as_txt.append(
                cls._format_field(
                    "Supported Post-Quantum groups:", cls._groups_to_text(result.supported_post_quantum_groups)
                )
            )
            assert result.rejected_post_quantum_groups is not None, "Should never happen"
            result_as_txt.append(
                cls._format_field(
                    "Rejected Post-Quantum groups:", cls._groups_to_text(result.rejected_post_quantum_groups)
                )
            )
        result_as_txt.append("")

        # Output for EC groups
        if result.supported_elliptic_curve_groups is None:
            result_as_txt.append(
                cls._format_field(
                    "Elliptic Curve Key Exchange:",
                    "VULNERABLE - The server does not support any cipher suites with an ECDH key exchange.",
                )
            )
        elif not result.supported_elliptic_curve_groups:
            result_as_txt.append(
                cls._format_field(
                    "Elliptic Curve Key Exchange:", "VULNERABLE - The server does not support any Elliptic Curve group."
                )
            )
            assert result.rejected_elliptic_curve_groups is not None, "Should never happen"
            result_as_txt.append(
                cls._format_field(
                    "Rejected Elliptic Curve groups:", cls._groups_to_text(result.rejected_elliptic_curve_groups)
                )
            )
        else:
            result_as_txt.append(
                cls._format_field(
                    "Elliptic Curve Key Exchange:", "OK - The server supports at least one Elliptic Curve group."
                )
            )
            result_as_txt.append(
                cls._format_field(
                    "Supported Elliptic Curve groups:", cls._groups_to_text(result.supported_elliptic_curve_groups)
                )
            )
            assert result.rejected_elliptic_curve_groups is not None, "Should never happen"
            result_as_txt.append(
                cls._format_field(
                    "Rejected Elliptic Curve groups:", cls._groups_to_text(result.rejected_elliptic_curve_groups)
                )
            )
        result_as_txt.append("")

        # FFDH output
        result_as_txt.append(
            cls._format_field(
                "Supported Finite Field DH groups:", cls._groups_to_text(result.supported_finite_field_dh_groups)
            )
        )
        result_as_txt.append(
            cls._format_field(
                "Rejected Finite Field DH groups:", cls._groups_to_text(result.rejected_finite_field_dh_groups)
            )
        )

        return result_as_txt


class SupportedGroupsImplementation(ScanCommandImplementation[SupportedGroupsScanResult, None]):
    """Test a server for Supported Groups, including Post-Quantum/Hybrid key exchange and Elliptic Curve groups."""

    cli_connector_cls = _SupportedGroupsCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: ScanCommandExtraArgument | None = None
    ) -> list[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        highest_tls_version_supported = server_info.tls_probing_result.highest_tls_version_supported
        if highest_tls_version_supported.value < TlsVersionEnum.TLS_1_0.value:
            # Nothing to test: the server does not support any usable TLS version
            return []

        # Figure out the list of groups and corresponding TLS versions to test for
        all_groups_and_tls_versions_to_test: list[tuple[OpenSslGroupNameEnum, TlsVersionEnum]]
        if highest_tls_version_supported.value < TlsVersionEnum.TLS_1_3.value:
            # The server does not support TLS 1.3
            # So some TLS 1.3-only groups (like PQ/hybrid groups) cannot be tested
            # Test all TLS 1.0-1.2 groups
            all_tls_1_2_groups = OpenSslGroupNameEnum.get_supported_by_tls_version(highest_tls_version_supported)
            all_groups_and_tls_versions_to_test = [(grp, highest_tls_version_supported) for grp in all_tls_1_2_groups]

        else:
            # The server does support TLS 1.3 : we test as many groups as possible on TLS 1.3, and the rest on TLS 1.2
            #  (so we assume the server supports TLS 1.2 as well)
            all_tls_1_3_groups = OpenSslGroupNameEnum.get_supported_by_tls_version(TlsVersionEnum.TLS_1_3)
            all_tls_1_2_groups = OpenSslGroupNameEnum.get_supported_by_tls_version(TlsVersionEnum.TLS_1_2)
            all_tls_1_2_groups_to_test = all_tls_1_2_groups - all_tls_1_3_groups

            all_groups_and_tls_versions_to_test = []
            all_groups_and_tls_versions_to_test.extend(
                [(group, TlsVersionEnum.TLS_1_3) for group in all_tls_1_3_groups]
            )
            all_groups_and_tls_versions_to_test.extend(
                [(group, TlsVersionEnum.TLS_1_2) for group in all_tls_1_2_groups_to_test]
            )

        # Queue all the scan jobs
        all_scan_jobs = []

        # Don't scan for EC groups if not ECDH cipher suites are supported
        is_ec_supported = server_info.tls_probing_result.supports_ecdh_key_exchange

        for group, tls_version in all_groups_and_tls_versions_to_test:
            if group.get_type() == OpenSslGroupTypeEnum.ELLIPTIC_CURVE:
                if is_ec_supported:
                    all_scan_jobs.append(
                        ScanJob(
                            # The logic for EC groups is slightly different
                            function_to_call=_test_ec_group,
                            function_arguments=[server_info, tls_version, group],
                        )
                    )
            else:
                all_scan_jobs.append(
                    ScanJob(
                        function_to_call=_test_pq_or_ffdh_group,
                        function_arguments=[server_info, tls_version, group],
                    )
                )

        return all_scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: list[ScanJobResult]
    ) -> SupportedGroupsScanResult:
        all_group_results: list[_SupportedGroupResult] = [job.get_result() for job in scan_job_results]
        all_ec_grp_results = [r for r in all_group_results if r.group.get_type() == OpenSslGroupTypeEnum.ELLIPTIC_CURVE]
        all_ffdh_grp_results = [
            r for r in all_group_results if r.group.get_type() == OpenSslGroupTypeEnum.FINITE_FIELD_DH
        ]
        all_pq_grp_results = [
            r
            for r in all_group_results
            if r.group.get_type() in (OpenSslGroupTypeEnum.POST_QUANTUM, OpenSslGroupTypeEnum.POST_QUANTUM_HYBRID)
        ]

        supported_elliptic_curve_groups: list[str] | None
        rejected_elliptic_curve_groups: list[str] | None
        does_server_support_ec = server_info.tls_probing_result.supports_ecdh_key_exchange
        if does_server_support_ec:
            supported_elliptic_curve_groups = [r.group for r in all_ec_grp_results if r.was_accepted_by_server]
            rejected_elliptic_curve_groups = [r.group for r in all_ec_grp_results if not r.was_accepted_by_server]
        else:
            supported_elliptic_curve_groups = None
            rejected_elliptic_curve_groups = None

        supported_post_quantum_groups: list[str] | None
        rejected_post_quantum_groups: list[str] | None
        does_server_support_tls_1_3 = (
            server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value
        )
        if does_server_support_tls_1_3:
            supported_post_quantum_groups = [r.group for r in all_pq_grp_results if r.was_accepted_by_server]
            rejected_post_quantum_groups = [r.group for r in all_pq_grp_results if not r.was_accepted_by_server]
        else:
            supported_post_quantum_groups = None
            rejected_post_quantum_groups = None

        return SupportedGroupsScanResult(
            supported_elliptic_curve_groups=supported_elliptic_curve_groups,
            rejected_elliptic_curve_groups=rejected_elliptic_curve_groups,
            supports_elliptic_curve_key_exchange=bool(supported_elliptic_curve_groups),
            supported_finite_field_dh_groups=[r.group for r in all_ffdh_grp_results if r.was_accepted_by_server],
            rejected_finite_field_dh_groups=[r.group for r in all_ffdh_grp_results if not r.was_accepted_by_server],
            supported_post_quantum_groups=supported_post_quantum_groups,
            rejected_post_quantum_groups=rejected_post_quantum_groups,
            supports_post_quantum_key_exchange=bool(supported_post_quantum_groups),
        )


@dataclass(frozen=True)
class _SupportedGroupResult:
    tls_version: TlsVersionEnum
    group: OpenSslGroupNameEnum
    was_accepted_by_server: bool


def _test_pq_or_ffdh_group(
    server_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, group: OpenSslGroupNameEnum
) -> _SupportedGroupResult:
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version,
        # Only the 4.0.0 client has support for the PQ groups
        openssl_version=OpenSslVersionEnum.OPENSSL_4_0_0,
    )
    assert isinstance(ssl_connection.ssl_client, SslClient_OpenSSL_4_0_0), "Should never happen"

    ssl_connection.ssl_client.set_groups_list([group])

    negotiated_group: str | None = None
    try:
        ssl_connection.connect()
        negotiated_group = ssl_connection.ssl_client.get_group_name()

    except ClientCertificateRequested:
        negotiated_group = ssl_connection.ssl_client.get_group_name()

    except (ServerRejectedTlsHandshake, TlsHandshakeTimedOut):
        negotiated_group = None

    finally:
        ssl_connection.close()

    if negotiated_group:
        assert negotiated_group == group, f"Should never happen: group should be {group} but got {negotiated_group}"

    return _SupportedGroupResult(
        tls_version=tls_version, group=group, was_accepted_by_server=negotiated_group is not None
    )


def _test_ec_group(
    server_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, curve_group: OpenSslGroupNameEnum
) -> _SupportedGroupResult:
    assert server_info.tls_probing_result.supports_ecdh_key_exchange, "Should never happen"

    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version, openssl_version=OpenSslVersionEnum.OPENSSL_4_0_0
    )
    assert isinstance(ssl_connection.ssl_client, SslClient_OpenSSL_4_0_0), "Should never happen"

    # Set curve to test whether it is supported by the server
    enable_ecdh_cipher_suites(tls_version, ssl_connection.ssl_client)
    ssl_connection.ssl_client.set_groups_list([curve_group])

    try:
        ssl_connection.connect()
        negotiated_ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()

    # Error handling here is similar to test_cipher_suite.py
    except ClientCertificateRequested:
        negotiated_ephemeral_key = ssl_connection.ssl_client.get_ephemeral_key()

    except (TlsHandshakeTimedOut, ServerRejectedTlsHandshake):
        negotiated_ephemeral_key = None

    except OpenSSLError as e:
        # The following errors can be triggered by some servers when they don't support the specific curve enabled
        # in the client
        if "ossl_statem_client_read_transition:unexpected message" in e.args[0]:
            # Related to https://github.com/nabla-c0d3/sslyze/issues/466
            negotiated_ephemeral_key = None
        elif "tls_process_ske_ecdhe:wrong curve" in e.args[0] or "sslv3 alert unexpected message" in e.args[0]:
            # https://github.com/nabla-c0d3/sslyze/issues/490
            negotiated_ephemeral_key = None
        elif "wrong curve" in e.args[0]:
            # https://github.com/nabla-c0d3/sslyze/issues/579
            negotiated_ephemeral_key = None
        else:
            raise

    finally:
        ssl_connection.close()

    if negotiated_ephemeral_key and isinstance(negotiated_ephemeral_key, EcDhEphemeralKeyInfo):
        # Ensure the negotiated curve is the one we requested
        negotiated_group = ssl_connection.ssl_client.get_group_name()
        assert negotiated_group == curve_group, (
            f"Should never happen: group should be {curve_group} but got {negotiated_group}"
        )
        assert negotiated_ephemeral_key.curve_name == curve_group, "Should never happen"
        was_accepted_by_server = True
    else:
        was_accepted_by_server = False

    return _SupportedGroupResult(
        tls_version=tls_version,
        group=curve_group,
        was_accepted_by_server=was_accepted_by_server,
    )
