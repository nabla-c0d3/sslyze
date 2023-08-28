from abc import ABC
from typing import Optional

try:
    # pydantic 2.x
    from pydantic.v1 import BaseModel  # TODO(#617): Remove v1
except ImportError:
    # pydantic 1.x
    from pydantic import BaseModel  # type: ignore

from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum, ScanCommandErrorReasonEnum


# Must be subclassed in order to add the result field
class ScanCommandAttemptAsJson(BaseModel, ABC):
    class Config:
        orm_mode = True
        extra = "forbid"  # Fields must match between the JSON representation and the actual objects

    status: ScanCommandAttemptStatusEnum
    error_reason: Optional[ScanCommandErrorReasonEnum]
    error_trace: Optional[str]
