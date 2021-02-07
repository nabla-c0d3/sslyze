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
from sslyze.plugins.session_resumption._resumption_with_id import (
    resume_with_session_id,
    _ScanJobResultEnum,
    TlsSessionIdSupportEnum,
    ServerOnlySupportsTls13,
)
from sslyze.plugins.session_resumption._resumption_with_ticket import (
    resume_with_tls_ticket,
    TlsSessionTicketSupportEnum,
)
from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class SessionResumptionSupportScanResult(ScanCommandResult):
    """The result of testing a server for TLS 1.2 session resumption support, using session IDs and TLS tickets.

    Attributes:
        session_id_resumption_result:
        attempted_session_id_resumptions_count: The total number of session ID resumptions that were attempted.
        successful_session_id_resumptions_count: The number of session ID resumptions that were successful.

        tls_ticket_resumption_result:
    """

    session_id_resumption_result: TlsSessionIdSupportEnum
    attempted_session_id_resumptions_count: int
    successful_session_id_resumptions_count: int

    tls_ticket_resumption_result: TlsSessionTicketSupportEnum

    # TODO(AD): Remove these properties for v5.0.0.
    @property
    def is_session_id_resumption_supported(self) -> bool:
        return self.session_id_resumption_result == TlsSessionIdSupportEnum.FULLY_SUPPORTED

    @property
    def is_tls_ticket_resumption_supported(self) -> bool:
        return self.tls_ticket_resumption_result == TlsSessionTicketSupportEnum.SUCCEEDED


@dataclass(frozen=True)
class SessionResumptionRateScanResult(ScanCommandResult):
    """The result of measuring a server's session resumption rate when attempting 100 resumptions using session IDs.

    Attributes:
        session_id_resumption_result:
        attempted_session_id_resumptions_count: The total number of session ID resumptions that were attempted.
        successful_session_id_resumptions_count: The number of session ID resumptions that were successful.
    """

    session_id_resumption_result: TlsSessionIdSupportEnum
    attempted_session_id_resumptions_count: int
    successful_session_id_resumptions_count: int


def _resumption_with_session_ids_result_to_console_output(
    session_id_resumption_result: TlsSessionIdSupportEnum,
    successful_session_id_resumptions_count: int,
    attempted_session_id_resumptions_count: int,
) -> str:
    if session_id_resumption_result == TlsSessionIdSupportEnum.FULLY_SUPPORTED:
        resumption_support_txt = "OK - Supported"
    elif session_id_resumption_result == TlsSessionIdSupportEnum.PARTIALLY_SUPPORTED:
        resumption_support_txt = "PARTIALLY SUPPORTED"
    elif session_id_resumption_result == TlsSessionIdSupportEnum.NOT_SUPPORTED:
        resumption_support_txt = "NOT SUPPORTED"
    elif session_id_resumption_result == TlsSessionIdSupportEnum.SERVER_IS_TLS_1_3_ONLY:
        resumption_support_txt = "OK - Server only supports TLS 1.3 which doesn't support Session IDs"
    else:
        raise ValueError(f"Unexpected value: {session_id_resumption_result}")

    if session_id_resumption_result != TlsSessionIdSupportEnum.SERVER_IS_TLS_1_3_ONLY:
        resum_rate_txt = (
            f" ({successful_session_id_resumptions_count} successful resumptions"
            f" out of {attempted_session_id_resumptions_count} attempts)"
        )
    else:
        resum_rate_txt = ""

    return f"      With Session IDs: {resumption_support_txt}{resum_rate_txt}."


class _SessionResumptionSupportCliConnector(ScanCommandCliConnector[SessionResumptionSupportScanResult, None]):

    _cli_option = "resum"
    _cli_description = "Test a server for session resumption support using session IDs and TLS tickets."

    @classmethod
    def result_to_console_output(cls, result: SessionResumptionSupportScanResult) -> List[str]:
        result_as_txt = [cls._format_title("TLS 1.2 Session Resumption Support")]

        # Resumption with session IDs
        result_as_txt.append(
            _resumption_with_session_ids_result_to_console_output(
                result.session_id_resumption_result,
                result.successful_session_id_resumptions_count,
                result.attempted_session_id_resumptions_count,
            )
        )

        # Resumption with TLS tickets
        if result.tls_ticket_resumption_result == TlsSessionTicketSupportEnum.SUCCEEDED:
            ticket_txt = "OK - Supported"
        elif result.tls_ticket_resumption_result == TlsSessionTicketSupportEnum.FAILED_ONLY_TLS_1_3_SUPPORTED:
            ticket_txt = "OK - Server only supports TLS 1.3 which doesn't support TLS tickets"
        elif result.tls_ticket_resumption_result == TlsSessionTicketSupportEnum.FAILED_TICKED_IGNORED:
            ticket_txt = "NOT SUPPORTED - Server returned a TLS ticket but then ignored it"
        elif result.tls_ticket_resumption_result == TlsSessionTicketSupportEnum.FAILED_TICKET_NOT_ASSIGNED:
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
                result.session_id_resumption_result,
                result.successful_session_id_resumptions_count,
                result.attempted_session_id_resumptions_count,
            )
        )
        return result_as_txt


def _create_resume_with_session_id_scan_jobs(
    server_info: ServerConnectivityInfo, resumption_attempts_nb: int
) -> List[ScanJob]:
    scan_jobs = [
        ScanJob(function_to_call=resume_with_session_id, function_arguments=[server_info])
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
            try:
                was_resumption_successful = job.result()
                if was_resumption_successful:
                    successful_resumptions_count += 1
            except ServerOnlySupportsTls13:
                # If the server only supports TLS 1.3, Session ID resumption is not supported by the server
                return SessionResumptionRateScanResult(
                    session_id_resumption_result=TlsSessionIdSupportEnum.SERVER_IS_TLS_1_3_ONLY,
                    attempted_session_id_resumptions_count=0,
                    successful_session_id_resumptions_count=0,
                )

        if successful_resumptions_count == 0:
            session_id_resumption_result = TlsSessionIdSupportEnum.NOT_SUPPORTED
        elif successful_resumptions_count == cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB:
            session_id_resumption_result = TlsSessionIdSupportEnum.FULLY_SUPPORTED
        else:
            session_id_resumption_result = TlsSessionIdSupportEnum.PARTIALLY_SUPPORTED

        return SessionResumptionRateScanResult(
            session_id_resumption_result=session_id_resumption_result,
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
        tls_ticket_scan_jobs = [ScanJob(function_to_call=resume_with_tls_ticket, function_arguments=[server_info])]

        return session_id_scan_jobs + tls_ticket_scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> SessionResumptionSupportScanResult:
        total_scan_jobs_count = cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB + 1  # Session ID jobs + 1 TLS ticket job
        if len(completed_scan_jobs) != total_scan_jobs_count:
            raise RuntimeError(f"Unexpected number of scan jobs received: {completed_scan_jobs}")

        # Sort TLS ticket VS session ID results
        results_dict: Dict[_ScanJobResultEnum, List[Any]] = {
            _ScanJobResultEnum.SESSION_ID_RESUMPTION: [],
            _ScanJobResultEnum.TLS_TICKET_RESUMPTION: [],
        }
        for job in completed_scan_jobs:
            try:
                result_enum, value = job.result()
                results_dict[result_enum].append(value)
            except ServerOnlySupportsTls13:
                # If the server only supports TLS 1.3, none of the resumption mechanisms in this plugin are supported
                # by the server
                return SessionResumptionSupportScanResult(
                    session_id_resumption_result=TlsSessionIdSupportEnum.SERVER_IS_TLS_1_3_ONLY,
                    attempted_session_id_resumptions_count=0,
                    successful_session_id_resumptions_count=0,
                    tls_ticket_resumption_result=TlsSessionTicketSupportEnum.FAILED_ONLY_TLS_1_3_SUPPORTED,
                )

        # Process session IDs resumption results
        successful_session_id_resumptions_count = 0
        for was_resumption_successful in results_dict[_ScanJobResultEnum.SESSION_ID_RESUMPTION]:
            if was_resumption_successful:
                successful_session_id_resumptions_count += 1

        if successful_session_id_resumptions_count == 0:
            session_id_resumption_result = TlsSessionIdSupportEnum.NOT_SUPPORTED
        elif successful_session_id_resumptions_count == cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB:
            session_id_resumption_result = TlsSessionIdSupportEnum.FULLY_SUPPORTED
        else:
            session_id_resumption_result = TlsSessionIdSupportEnum.PARTIALLY_SUPPORTED

        # All done
        return SessionResumptionSupportScanResult(
            session_id_resumption_result=session_id_resumption_result,
            attempted_session_id_resumptions_count=cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB,
            successful_session_id_resumptions_count=successful_session_id_resumptions_count,
            tls_ticket_resumption_result=results_dict[_ScanJobResultEnum.TLS_TICKET_RESUMPTION][0],
        )
