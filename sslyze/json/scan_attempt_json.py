from abc import ABC
from typing import Optional

import pydantic

from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum, ScanCommandErrorReasonEnum


# Must be subclassed in order to add the result field
class ScanCommandAttemptAsJson(pydantic.BaseModel, ABC):
    class Config:
        orm_mode = True
        extra = "forbid"  # Fields must match between the JSON representation and the actual objects

    status: ScanCommandAttemptStatusEnum
    error_reason: Optional[ScanCommandErrorReasonEnum]
    error_trace: Optional[str]
