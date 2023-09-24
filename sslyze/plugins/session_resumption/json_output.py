from typing import Optional

from sslyze import SessionResumptionSupportExtraArgument, SessionResumptionSupportScanResult, TlsResumptionSupportEnum
from sslyze.json.pydantic_utils import BaseModelWithOrmModeAndForbid
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson


class SessionResumptionSupportExtraArgumentAsJson(BaseModelWithOrmModeAndForbid):
    number_of_resumptions_to_attempt: int


assert SessionResumptionSupportExtraArgument.__doc__
SessionResumptionSupportExtraArgumentAsJson.__doc__ = SessionResumptionSupportExtraArgument.__doc__


class SessionResumptionSupportScanResultAsJson(BaseModelWithOrmModeAndForbid):
    session_id_resumption_result: TlsResumptionSupportEnum
    session_id_attempted_resumptions_count: int
    session_id_successful_resumptions_count: int

    tls_ticket_resumption_result: TlsResumptionSupportEnum
    tls_ticket_attempted_resumptions_count: int
    tls_ticket_successful_resumptions_count: int


assert SessionResumptionSupportScanResult.__doc__
SessionResumptionSupportScanResultAsJson.__doc__ = SessionResumptionSupportScanResult.__doc__


class SessionResumptionSupportScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[SessionResumptionSupportScanResultAsJson]
