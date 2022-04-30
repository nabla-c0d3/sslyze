from dataclasses import dataclass
from typing import Optional, List, Tuple
from unittest import mock

import pytest

from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandExtraArgument,
    ScanJob,
    ScanJobResult,
    ScanCommandResult,
)
from sslyze.plugins.scan_commands import ScanCommandsRepository
from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class MockPluginScanResult(ScanCommandResult):
    results_field: List[str]
    did_receive_extra_arguments: bool = False


class _MockPluginImplementation(ScanCommandImplementation):

    result_cls = MockPluginScanResult
    _scan_jobs_count = 5

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        # Create a bunch of "do nothing" jobs to imitate a real plugin
        did_receive_extra_arguments = extra_arguments is not None
        scan_jobs = [
            ScanJob(
                function_to_call=cls._scan_job_work_function,
                function_arguments=["test", 12, did_receive_extra_arguments],
            )
            for _ in range(cls._scan_jobs_count)
        ]
        return scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> ScanCommandResult:
        if len(scan_job_results) != cls._scan_jobs_count:
            raise AssertionError("Did not receive all the scan jobs that needed to be completed")

        results_field = []
        for job_result in scan_job_results:
            result_str, did_receive_extra_arguments = job_result.get_result()
            results_field.append(result_str)

        return cls.result_cls(results_field=results_field, did_receive_extra_arguments=did_receive_extra_arguments)

    @staticmethod
    def _scan_job_work_function(arg1: str, arg2: int, did_receive_extra_arguments: bool) -> Tuple[str, bool]:
        return f"{arg1}-{arg2}-did nothing", did_receive_extra_arguments


@pytest.fixture
def mock_scan_commands():
    """Make all scan commands point to a mock implementation so that no actual scans are performed."""
    with mock.patch.object(ScanCommandsRepository, "get_implementation_cls", return_value=_MockPluginImplementation):
        yield
