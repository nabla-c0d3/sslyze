from concurrent.futures._base import Future
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from nassl.ssl_client import OpenSslVersionEnum

from sslyze.plugins.plugin_base import ScanCommandResult, ScanCommandImplementation, ScanCommandExtraArguments, ScanJob
from sslyze.plugins.session_resumption.resumption_with_id import resume_with_session_id, _ScanJobResultEnum
from sslyze.plugins.session_resumption.resumption_with_ticket import resume_with_tls_ticket, TslSessionTicketSupportEnum
from sslyze.server_connectivity import ServerConnectivityInfo


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
    """The result of measuring a server's session resumption rate when using session IDs.

    Attributes:
        attempted_session_id_resumptions_count: The total number of session ID resumptions that were attempted.
        successful_session_id_resumptions_count: The number of session ID resumptions that were successful.
    """

    attempted_session_id_resumptions_count: int
    successful_session_id_resumptions_count: int


def _create_resume_with_session_id_scan_jobs(server_info, resumption_attempts_nb: int) -> List[ScanJob]:
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher as session resumption is different with TLS 1.3
    if server_info.tls_probing_result.highest_tls_version_supported >= OpenSslVersionEnum.TLSV1_3:
        tls_version_to_use = OpenSslVersionEnum.TLSV1_2
    else:
        tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported

    scan_jobs = [
        ScanJob(function_to_call=resume_with_session_id, function_arguments=[server_info, tls_version_to_use])
        for _ in range(resumption_attempts_nb)
    ]
    return scan_jobs


class SessionResumptionRateImplementation(ScanCommandImplementation):
    """Measure a server's session resumption rate when using session IDs by attempting 100 resumptions.
    """

    _SESSION_ID_RESUMPTION_ATTEMPTS_NB = 100

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ValueError("This plugin does not take extra arguments")

        return _create_resume_with_session_id_scan_jobs(server_info, cls._SESSION_ID_RESUMPTION_ATTEMPTS_NB)

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
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


class SessionResumptionSupportImplementation(ScanCommandImplementation):
    """Test a server for session resumption support using session IDs and TLS tickets.
    """

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
        if server_info.tls_probing_result.highest_tls_version_supported >= OpenSslVersionEnum.TLSV1_3:
            tls_version_to_use = OpenSslVersionEnum.TLSV1_2
        else:
            tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported

        tls_ticket_scan_jobs = [
            ScanJob(function_to_call=resume_with_tls_ticket, function_arguments=[server_info, tls_version_to_use])
        ]

        return session_id_scan_jobs + tls_ticket_scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
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


# TODO
class CliConnector:

    RESUMPTION_LINE_FORMAT = "      {resumption_type:<35}{result}"

    def as_text(self) -> List[str]:
        # Same output as --resum_rate but add a line about TLS ticket resumption at the end
        result_txt = self._rate_result.as_text()

        if self.ticket_resumption_error:
            ticket_txt = "ERROR: {}".format(self.ticket_resumption_error)
        else:
            ticket_txt = (
                "OK - Supported"
                if self.is_ticket_resumption_supported
                else "NOT SUPPORTED - {}.".format(self.ticket_resumption_failed_reason)
            )

        result_txt.append(self.RESUMPTION_LINE_FORMAT.format(resumption_type="With TLS Tickets:", result=ticket_txt))
        return result_txt

    RESUMPTION_RESULT_FORMAT = "{4} ({0} successful, {1} failed, {2} errors, {3} total attempts)."
    RESUMPTION_LINE_FORMAT = "      {resumption_type:<35}{result}"
    RESUMPTION_ERROR_FORMAT = "        ERROR #{error_nb}: {error_msg}"

    def as_text(self) -> List[str]:
        result_txt = [self._format_title(self.scan_command.get_title())]

        # Create the line which summarizes the session resumption rate
        if self.successful_resumptions_nb == self.attempted_resumptions_nb:
            resumption_supported_txt = "OK - Supported"
        elif self.successful_resumptions_nb > 0:
            resumption_supported_txt = "PARTIALLY SUPPORTED"
        elif self.failed_resumptions_nb == self.attempted_resumptions_nb:
            resumption_supported_txt = "NOT SUPPORTED"
        else:
            resumption_supported_txt = "ERROR"

        resum_rate_txt = self.RESUMPTION_RESULT_FORMAT.format(
            str(self.successful_resumptions_nb),
            str(self.failed_resumptions_nb),
            str(len(self.errored_resumptions_list)),
            str(self.attempted_resumptions_nb),
            resumption_supported_txt,
        )
        result_txt.append(
            self.RESUMPTION_LINE_FORMAT.format(resumption_type="With Session IDs:", result=resum_rate_txt)
        )

        # Add error messages if there was any
        i = 0
        for error_msg in self.errored_resumptions_list:
            result_txt.append(self.RESUMPTION_ERROR_FORMAT.format(error_nb=i, error_msg=error_msg))
            i += 1

        return result_txt
