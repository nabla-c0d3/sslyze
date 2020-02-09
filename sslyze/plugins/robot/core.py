from concurrent.futures._base import Future
from dataclasses import dataclass
from typing import Optional, List, Dict

from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanCommandExtraArguments,
    ScanJob,
    ScanCommandWrongUsageError,
)

from sslyze.plugins.robot.robot_tester import (
    RobotScanResultEnum,
    test_robot,
    ServerDoesNotSupportRsa,
    RobotPmsPaddingPayloadEnum,
    RobotServerResponsesAnalyzer,
)
from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class RobotScanResult(ScanCommandResult):
    """The result of testing a server for the ROBOT vulnerability.

    Attributes:
        robot_result_enum: An Enum providing the result of the ROBOT scan.
    """

    result: RobotScanResultEnum


class RobotImplementation(ScanCommandImplementation):

    _TEST_ATTEMPTS_NB = 3

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        # Run the test three times to ensure the results are consistent
        return [
            ScanJob(function_to_call=test_robot, function_arguments=[server_info]) for _ in range(cls._TEST_ATTEMPTS_NB)
        ]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
        if len(completed_scan_jobs) != cls._TEST_ATTEMPTS_NB:
            raise RuntimeError(f"Unexpected number of scan jobs received: {completed_scan_jobs}")

        combined_server_responses: Dict[RobotPmsPaddingPayloadEnum, List[str]] = {
            payload_enum: [] for payload_enum in RobotPmsPaddingPayloadEnum
        }
        for future in completed_scan_jobs:
            try:
                server_responses_per_robot_payloads = future.result()
                for payload_enum, server_response in server_responses_per_robot_payloads.items():
                    combined_server_responses[payload_enum].append(server_response)
            except ServerDoesNotSupportRsa:
                return RobotScanResult(result=RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED)

        result = RobotServerResponsesAnalyzer(combined_server_responses, cls._TEST_ATTEMPTS_NB).compute_result_enum()
        return RobotScanResult(result)


# TODO
class CliConnector:
    def as_text(self) -> List[str]:
        if self.robot_result_enum == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
            robot_txt = "VULNERABLE - Strong oracle, a real attack is possible"
        elif self.robot_result_enum == RobotScanResultEnum.VULNERABLE_WEAK_ORACLE:
            robot_txt = "VULNERABLE - Weak oracle, the attack would take too long"
        elif self.robot_result_enum == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE:
            robot_txt = "OK - Not vulnerable"
        elif self.robot_result_enum == RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED:
            robot_txt = "OK - Not vulnerable, RSA cipher suites not supported"
        elif self.robot_result_enum == RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS:
            robot_txt = "UNKNOWN - Received inconsistent results"
        else:
            raise ValueError("Should never happen")

        return [self._format_title(self.scan_command.get_title()), self._format_field("", robot_txt)]
