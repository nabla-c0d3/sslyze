"""A few plugins that really do nothing but used by the test suite to replicate a real plugin's behavior.
"""

from concurrent.futures import Future
from dataclasses import dataclass
from typing import Optional, List, ClassVar, Type, Dict, Set

from sslyze.plugins.plugin_base import ScanCommandImplementation, ScanJob, ScanCommandResult, ScanCommandExtraArguments
from sslyze.server_connectivity import ServerConnectivityInfo

try:
    # Python 3.7
    from typing_extensions import Literal
except ModuleNotFoundError:
    # Python 3.8+
    from typing import Literal  # type: ignore


ScanCommandForTestsType = Literal[
    "mock1", "mock2", "mock3", "mock4",
]


class ScanCommandForTests:
    MOCK_COMMAND_1: Literal["mock1"] = "mock1"
    MOCK_COMMAND_2: Literal["mock2"] = "mock2"

    def get_implementation_cls(self):
        return _IMPLEMENTATION_CLASSES[self]


class ScanCommandForTestsRepository:
    @staticmethod
    def get_implementation_cls(scan_command: ScanCommandForTestsType) -> Type["ScanCommandImplementation"]:
        return _IMPLEMENTATION_CLASSES[scan_command]

    @staticmethod
    def get_all_scan_commands() -> Set[ScanCommandForTestsType]:
        return set(_IMPLEMENTATION_CLASSES.keys())


@dataclass(frozen=True)
class MockPlugin1ExtraArguments(ScanCommandExtraArguments):
    extra_field: str


@dataclass(frozen=True)
class _MockPluginScanResult(ScanCommandResult):
    results_field: List[str]


class MockPlugin1ScanResult(_MockPluginScanResult):
    pass


class MockPlugin2ScanResult(_MockPluginScanResult):
    pass


class _MockPluginImplementation(ScanCommandImplementation):

    result_cls: ClassVar[Type[ScanCommandResult]]
    _scan_jobs_count = 5

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[MockPlugin1ExtraArguments] = None
    ) -> List[ScanJob]:
        # Create a bunch of "do nothing" jobs to imitate a real plugin
        scan_jobs = [
            ScanJob(function_to_call=cls._scan_job_work_function, function_arguments=["test", 12])
            for _ in range(cls._scan_jobs_count)
        ]
        return scan_jobs

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
        if len(completed_scan_jobs) != cls._scan_jobs_count:
            raise AssertionError("Did not receive all the scan jobs that needed to be completed")

        return cls.result_cls(results_field=[future.result() for future in completed_scan_jobs])  # type: ignore

    @staticmethod
    def _scan_job_work_function(arg1: str, arg2: int) -> str:
        return f"{arg1}-{arg2}-did nothing"


class MockPlugin1Implementation(_MockPluginImplementation):
    result_cls = MockPlugin1ScanResult


class MockPlugin2Implementation(_MockPluginImplementation):
    result_cls = MockPlugin2ScanResult


_IMPLEMENTATION_CLASSES: Dict[ScanCommandForTestsType, Type["ScanCommandImplementation"]] = {
    ScanCommandForTests.MOCK_COMMAND_1: MockPlugin1Implementation,
    ScanCommandForTests.MOCK_COMMAND_2: MockPlugin2Implementation,
}
