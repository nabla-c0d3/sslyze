from abc import ABC
from typing import Optional
from pydantic import BaseModel, ConfigDict

from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum, ScanCommandErrorReasonEnum


# Must be subclassed in order to add the result field
class ScanCommandAttemptAsJson(BaseModel, ABC):
    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,  # Fields must match between the JSON representation and the actual objects
    )

    status: ScanCommandAttemptStatusEnum
    error_reason: Optional[ScanCommandErrorReasonEnum]
    error_trace: Optional[str]
