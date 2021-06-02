from dataclasses import dataclass
from enum import Enum
from traceback import TracebackException
from typing import Generic, Optional, TypeVar


# These are in a separate file to avoid cyclic imports
_ScanCommandResultTypeVar = TypeVar("_ScanCommandResultTypeVar")


class ScanCommandAttemptStatusEnum(str, Enum):
    ERROR = "ERROR"
    COMPLETED = "COMPLETED"
    NOT_SCHEDULED = "NOT_SCHEDULED"


class ScanCommandErrorReasonEnum(str, Enum):
    BUG_IN_SSLYZE = "BUG_IN_SSLYZE"
    CLIENT_CERTIFICATE_NEEDED = "CLIENT_CERTIFICATE_NEEDED"
    CONNECTIVITY_ISSUE = "CONNECTIVITY_ISSUE"
    WRONG_USAGE = "WRONG_USAGE"


@dataclass(frozen=True)
class ScanCommandAttempt(Generic[_ScanCommandResultTypeVar]):
    status: ScanCommandAttemptStatusEnum

    # Set if status == ERROR
    error_reason: Optional[ScanCommandErrorReasonEnum]
    error_trace: Optional[TracebackException]

    # Set if status == COMPLETED
    result: Optional[_ScanCommandResultTypeVar]
