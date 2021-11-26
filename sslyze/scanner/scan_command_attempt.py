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
    """The result of a single scan command.

    Attributes:
        status: Whether this specific scan command was ran successfully.
        error_reason: The reason why the scan command failed; None if the scan command succeeded.
        error_trace: The exception trace of when the scan command failed; None if the scan command succeeded.
        result: The actual result of the scan command; None if the scan command failed. The type of this attribute is
            the "ScanResult" object corresponding to the scan command.
    """

    status: ScanCommandAttemptStatusEnum

    # Set if status == ERROR
    error_reason: Optional[ScanCommandErrorReasonEnum]
    error_trace: Optional[TracebackException]

    # Set if status == COMPLETED
    result: Optional[_ScanCommandResultTypeVar]
