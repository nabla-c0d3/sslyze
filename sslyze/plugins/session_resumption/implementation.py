from concurrent.futures._base import Future
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanCommandExtraArguments,
    ScanJob,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
)
from sslyze.plugins.session_resumption._resumption_with_id import resume_with_session_id, _ScanJobResultEnum
from sslyze.plugins.session_resumption._resumption_with_ticket import (
    resume_with_tls_ticket,
    TslSessionTicketSupportEnum,
)
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


@dataclass(frozen=True)
class SessionResumptionSupportScanResult(ScanCommandResult):
    """The result of testing a server for session resumption support using session IDs and TLS tickets.

    Attributes:
        is_session_id_resumption_supported:
        attempted_session_id_resumptions_count: The total number of session ID resumptions that were attempted.
        successful_session_id_resumptions_count: The number of session ID resumptions that were successful.

        is_tls_ticket_resumption_supported: True if the server support TLS ticket resumption.
        tls_ticket_resumption_result:
    """

    attempted_session_id_resumptions_count: int
    successful_session_id_resumptions_count: int

    tls_ticket_resumption_result: TslSessionTicketSupportEnum

    @property
    def is_session_id_resumption_supported(self) -> bool:
        return (
            True
            if self.attempted_session_id_resumptions_count == self.successful_session_id_resumptions_count
            else False
        )

    @property
    def is_tls_ticket_resumption_supported(self) -> bool:
        return self.tls_ticket_resumption_result == TslSessionTicketSupportEnum.SUCCEEDED


@dataclass(frozen=True)
class SessionResumptionRateScanResult(ScanCommandResult):
    """The result of measuring a server's session resumption rate when attempting 100 resumptions using session IDs.

    Attributes:
        attempted_session_id_resumptions_count: The total number of session ID resumptions that were attempted.
        successful_session_id_resumptions_count: The number of session ID resumptions that were successful.
    """

    attempted_session_id_resumptions_count: int
    successful_session_id_resumptions_count: int


def _resumption_with_session_ids_result_to_console_output(
    successful_session_id_resumptions_count: int, attempted_session_id_resumptions_count: int
) -> str:
    if successful_session_id_resumptions_count == attempted_session_id_resumptions_count:
        resumption_support_txt = "OK - Supported"
    elif successful_session_id_resumptions_count > 0:
        resumption_support_txt = "PARTIALLY SUPPORTED"
    else:
        resumption_support_txt = "NOT SUPPORTED"

    resum_rate_txt = (
        f"{resumption_support_txt} ({successful_session_id_resumptions_count} successful resumptions"
        f" out of {attempted_session_id_resumptions_count} attempts)."
    )

    return f"      With Session IDs: {resum_rate_txt}"


class _SessionResumptionSupportCliConnector(ScanCommandCliConnector[SessionResumptionSupportScanResult, None]):

    _cli_option = "resum"
    _cli_description = "Test a server for session resumption support using session IDs and TLS tickets."

    @classmethod
    def result_to_console_output(cls, result: SessionResumptionSupportScanResult) -> List[str]:
        result_as_txt = [cls._format_title("TLS 1.2 Session Resumption Support")]

        # Resumption with session IDs
        result_as_txt.append(
            _resumption_with_session_ids_result_to_console_output(
                result.successful_session_id_resumptions_count, result.attempted_session_id_resumptions_count
            )
        )

        # Resumption with TLS tickets
        if result.tls_ticket_resumption_result == TslSessionTicketSupportEnum.SUCCEEDED:
            ticket_txt = "OK - Supported"
        elif result.tls_ticket_resumption_result == TslSessionTicketSupportEnum.FAILED_ONLY_TLS_1_3_SUPPORTED:
            ticket_txt = "OK - Server only supports TLS 1.3 which doesn't support TLS tickets"
        elif result.tls_ticket_resumption_result == TslSessionTicketSupportEnum.FAILED_TICKED_IGNORED:
            ticket_txt = "NOT SUPPORTED - Server returned a TLS ticket but then ignored it"
        elif result.tls_ticket_resumption_result == TslSessionTicketSupportEnum.FAILED_TICKET_NOT_ASSIGNED:
            ticket_txt = "NOT SUPPORTED - Server did not return a TLS ticket"
        else:
            raise ValueError("Should never happen")

        result_as_txt.append(f"      With TLS Tickets: {ticket_txt}.")
        return result_as_txt


class _SessionResumptionRateSupportCliConnector(ScanCommandCliConnector[SessionResumptionRateScanResult, None]):

    _cli_option = "resum_rate"
    _cli_description = "Measure a server's session resumption rate when attempting 100 resumptions using session IDs."

    @classmethod
    def result_to_console_output(cls, result: SessionResumptionRateScanResult) -> List[str]:
        result_as_txt = [cls._format_title("TLS 1.2 Session Resumption Rate")]
        result_as_txt.append(
            _resumption_with_session_ids_result_to_console_output(
                result.successful_session_id_resumptions_count, result.attempted_session_id_resumptions_count
            )
        )
        return result_as_txt


def _create_resume_with_session_id_scan_jobs(
    server_info: ServerConnectivityInfo, resumption_attempts_nb: int
) -> List[ScanJob]:
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as session resumption is different with TLS 1.3
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        tls_version_to_use = TlsVersionEnum.TLS_1_2
    else:
        tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported

    scan_jobs = [
        ScanJob(function_to_call=resume_with_session_id, function_arguments=[server_info, tls_version_to_use])
        for _ in range(resumption_attempts_nb)
    ]
    return scan_jobs


class SessionResumptionRateImplementation(ScanCommandImplementation[SessionResumptionRateScanResult, None]):
    """Measure a server's session resumption rate when using session IDs by attempting 100 resumptions.
    """

    cli_connector_cls = _SessionResumptionRateSupportCliConnector

    _SESSION_ID_RESUMPTION_ATTEMPTS_NB = 100

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return _create_resume_with_session_id_scan_jobs(server_info, cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB)

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> SessionResumptionRateScanResult:
        if len(completed_scan_jobs) != cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB:
            raise RuntimeError(f"Unexpected number of scan jobs received: {completed_scan_jobs}")

        successful_resumptions_count = 0
        for job in completed_scan_jobs:
            was_resumption_successful = job.result()
            if was_resumption_successful:
                successful_resumptions_count += 1

        return SessionResumptionRateScanResult(
            attempted_session_id_resumptions_count=cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB,
            successful_session_id_resumptions_count=successful_resumptions_count,
        )


class SessionResumptionSupportImplementation(ScanCommandImplementation[SessionResumptionSupportScanResult, None]):
    """Test a server for session resumption support using session IDs and TLS tickets.
    """

    cli_connector_cls = _SessionResumptionSupportCliConnector

    _SESSION_ID_RESUMPTION_ATTEMPTS_NB = 5

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ValueError("This plugin does not take extra arguments")

        # Test Session ID support
        session_id_scan_jobs = _create_resume_with_session_id_scan_jobs(
            server_info, cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB
        )

        # Test TLS tickets support
        # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as session resumption is different with TLS 1.3
        if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
            tls_version_to_use = TlsVersionEnum.TLS_1_2
        else:
            tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported

        tls_ticket_scan_jobs = [
            ScanJob(function_to_call=resume_with_tls_ticket, function_arguments=[server_info, tls_version_to_use])
        ]

        return session_id_scan_jobs + tls_ticket_scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> SessionResumptionSupportScanResult:
        total_scan_jobs_count = cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB + 1  # Session ID jobs + 1 TLS ticket job
        if len(completed_scan_jobs) != total_scan_jobs_count:
            raise RuntimeError(f"Unexpected number of scan jobs received: {completed_scan_jobs}")

        # Sort TLS ticket VS session ID result
        results_dict: Dict[_ScanJobResultEnum, List[Any]] = {
            _ScanJobResultEnum.SESSION_ID_RESUMPTION: [],
            _ScanJobResultEnum.TLS_TICKET_RESUMPTION: [],
        }
        for job in completed_scan_jobs:
            result_enum, value = job.result()
            results_dict[result_enum].append(value)

        successful_session_id_resumptions_count = 0
        for was_resumption_successful in results_dict[_ScanJobResultEnum.SESSION_ID_RESUMPTION]:
            if was_resumption_successful:
                successful_session_id_resumptions_count += 1

        return SessionResumptionSupportScanResult(
            attempted_session_id_resumptions_count=cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB,
            successful_session_id_resumptions_count=successful_session_id_resumptions_count,
            tls_ticket_resumption_result=results_dict[_ScanJobResultEnum.TLS_TICKET_RESUMPTION][0],
        )
