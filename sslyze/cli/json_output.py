import json
from dataclasses import asdict, dataclass
from typing import TextIO, List

from sslyze.__version__ import __url__, __version__
from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.cli.output_generator import OutputGenerator
from sslyze.errors import ConnectionToServerFailed
from sslyze.json import JsonEncoder
from sslyze.scanner import ServerScanResult
from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class _ServerConnectivityErrorAsJson:
    server_string: str
    error_message: str


@dataclass(frozen=True)
class _SslyzeOutputAsJson:
    """The "root" dictionary of the JSON output when using the --json command line option.
    """

    server_scan_results: List[ServerScanResult]
    server_connectivity_errors: List[_ServerConnectivityErrorAsJson]
    total_scan_time: float
    sslyze_version: str = __version__
    sslyze_url: str = __url__


class JsonOutputGenerator(OutputGenerator):
    def __init__(self, file_to: TextIO) -> None:
        super().__init__(file_to)
        self._server_connectivity_errors: List[_ServerConnectivityErrorAsJson] = []
        self._server_scan_results: List[ServerScanResult] = []

    def command_line_parsed(self, parsed_command_line: ParsedCommandLine) -> None:
        for bad_server_str in parsed_command_line.invalid_servers:
            self._server_connectivity_errors.append(
                _ServerConnectivityErrorAsJson(
                    server_string=bad_server_str.server_string, error_message=bad_server_str.error_message
                )
            )

    def server_connectivity_test_failed(self, connectivity_error: ConnectionToServerFailed) -> None:
        hostname = connectivity_error.server_location.hostname
        port = connectivity_error.server_location.port
        self._server_connectivity_errors.append(
            _ServerConnectivityErrorAsJson(
                server_string=f"{hostname}:{port}", error_message=connectivity_error.error_message,
            )
        )

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        pass

    def scans_started(self) -> None:
        pass

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        self._server_scan_results.append(server_scan_result)

    def scans_completed(self, total_scan_time: float) -> None:
        final_json_output = _SslyzeOutputAsJson(
            server_scan_results=self._server_scan_results,
            server_connectivity_errors=self._server_connectivity_errors,
            total_scan_time=total_scan_time,
        )
        final_json_output_as_dict = asdict(final_json_output)
        json_out = json.dumps(final_json_output_as_dict, cls=JsonEncoder, sort_keys=True, indent=4, ensure_ascii=True)
        self._file_to.write(json_out)
