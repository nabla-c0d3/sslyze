from typing import Optional

import pydantic

from sslyze import SessionResumptionSupportExtraArgument, SessionResumptionSupportScanResult, TlsResumptionSupportEnum
from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson


class _BaseModelWithForbidAndOrmMode(pydantic.BaseModel):
    class Config:
        orm_mode = True
        extra = "forbid"  # Fields must match between the JSON representation and the result objects


class SessionResumptionSupportExtraArgumentAsJson(_BaseModelWithForbidAndOrmMode):
    number_of_resumptions_to_attempt: int


SessionResumptionSupportExtraArgumentAsJson.__doc__ = SessionResumptionSupportExtraArgument.__doc__  # type: ignore


class SessionResumptionSupportScanResultAsJson(_BaseModelWithForbidAndOrmMode):
    session_id_resumption_result: TlsResumptionSupportEnum
    session_id_attempted_resumptions_count: int
    session_id_successful_resumptions_count: int

    tls_ticket_resumption_result: TlsResumptionSupportEnum
    tls_ticket_attempted_resumptions_count: int
    tls_ticket_successful_resumptions_count: int


SessionResumptionSupportScanResultAsJson.__doc__ = SessionResumptionSupportScanResult.__doc__  # type: ignore


class SessionResumptionSupportScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[SessionResumptionSupportScanResultAsJson]
