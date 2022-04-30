from dataclasses import dataclass
from typing import Optional, List, Dict

import pydantic

from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanCommandExtraArgument,
    ScanJob,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
    ScanJobResult,
)

from sslyze.plugins.robot._robot_tester import (
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
        result: An Enum providing the result of the ROBOT scan.
    """

    robot_result: RobotScanResultEnum


# Identical fields in the JSON output
RobotScanResultAsJson = pydantic.dataclasses.dataclass(RobotScanResult, frozen=True)


class RobotScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[RobotScanResultAsJson]  # type: ignore


class _RobotCliConnector(ScanCommandCliConnector[RobotScanResult, None]):

    _cli_option = "robot"
    _cli_description = "Test a server for the ROBOT vulnerability."

    @classmethod
    def result_to_console_output(cls, result: RobotScanResult) -> List[str]:
        result_as_txt = [cls._format_title("ROBOT Attack")]

        if result.robot_result == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
            robot_txt = "VULNERABLE - Strong oracle, a real attack is possible."
        elif result.robot_result == RobotScanResultEnum.VULNERABLE_WEAK_ORACLE:
            robot_txt = "VULNERABLE - Weak oracle, the attack would take too long."
        elif result.robot_result == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE:
            robot_txt = "OK - Not vulnerable."
        elif result.robot_result == RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED:
            robot_txt = "OK - Not vulnerable, RSA cipher suites not supported."
        elif result.robot_result == RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS:
            robot_txt = "UNKNOWN - Received inconsistent results."
        else:
            raise ValueError("Should never happen")
        result_as_txt.append(cls._format_field("", robot_txt))
        return result_as_txt


class RobotImplementation(ScanCommandImplementation[RobotScanResult, None]):
    """Test a server for the ROBOT vulnerability."""

    cli_connector_cls = _RobotCliConnector

    _TEST_ATTEMPTS_NB = 3

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        # Run the test three times to ensure the results are consistent
        return [
            ScanJob(function_to_call=test_robot, function_arguments=[server_info]) for _ in range(cls._TEST_ATTEMPTS_NB)
        ]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> RobotScanResult:
        if len(scan_job_results) != cls._TEST_ATTEMPTS_NB:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        combined_server_responses: Dict[RobotPmsPaddingPayloadEnum, List[str]] = {
            payload_enum: [] for payload_enum in RobotPmsPaddingPayloadEnum
        }
        for future in scan_job_results:
            try:
                server_responses_per_robot_payloads = future.get_result()
                for payload_enum, server_response in server_responses_per_robot_payloads.items():
                    combined_server_responses[payload_enum].append(server_response)
            except ServerDoesNotSupportRsa:
                return RobotScanResult(robot_result=RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED)

        result = RobotServerResponsesAnalyzer(combined_server_responses, cls._TEST_ATTEMPTS_NB).compute_result_enum()
        return RobotScanResult(result)
