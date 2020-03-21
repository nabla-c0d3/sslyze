import copyreg
import json
from base64 import b64encode
from dataclasses import asdict, dataclass
from datetime import datetime
from functools import singledispatch
from pathlib import Path
from traceback import TracebackException
from typing import Dict, Any, TextIO, Union, List, Set

from enum import Enum
from sslyze import PROJECT_URL, __version__
from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.cli.output_generator import OutputGenerator
from sslyze.connection_helpers.errors import ConnectionToServerFailed
from sslyze.plugins.plugin_base import ScanCommandResult, ScanCommandExtraArguments
from sslyze.plugins.scan_commands import ScanCommandEnum
from sslyze.scanner import ServerScanResult, ScanCommandError
from sslyze.server_connectivity import ServerConnectivityInfo


@dataclass(frozen=True)
class _ServerConnectivityErrorAsJson:
    server_string: str
    error_message: str


@dataclass(frozen=True)
class _ServerScanResultAsJson:
    scan_commands_results: Dict[str, ScanCommandResult]
    scan_commands_errors: Dict[str, ScanCommandError]

    # What was passed in the corresponding ServerScanRequest
    server_info: "ServerConnectivityInfo"
    scan_commands: Set["ScanCommandEnum"]
    scan_commands_extra_arguments: Dict[str, ScanCommandExtraArguments]

    @classmethod
    def from_server_scan_result(cls, server_scan_result: ServerScanResult) -> "_ServerScanResultAsJson":
        return cls(
            server_info=server_scan_result.server_info,
            scan_commands=server_scan_result.scan_commands,
            # The JSON encoder does not like dictionaries with enums as keys
            # Fix that by converting enum keys into their enum names
            scan_commands_results={
                scan_cmd.name: value for scan_cmd, value in server_scan_result.scan_commands_results.items()
            },
            scan_commands_errors={
                scan_cmd.name: value for scan_cmd, value in server_scan_result.scan_commands_errors.items()
            },
            scan_commands_extra_arguments={
                scan_cmd.name: value for scan_cmd, value in server_scan_result.scan_commands_extra_arguments.items()
            },
        )


@dataclass(frozen=True)
class _SslyzeOutputAsJson:
    server_scan_results: List[_ServerScanResultAsJson]
    server_connectivity_errors: List[_ServerConnectivityErrorAsJson]
    total_scan_time: float
    sslyze_version: str = __version__
    sslyze_url: str = PROJECT_URL


class JsonOutputGenerator(OutputGenerator):
    def __init__(self, file_to: TextIO) -> None:
        super().__init__(file_to)
        self._server_connectivity_errors: List[_ServerConnectivityErrorAsJson] = []
        self._server_scan_results: List[_ServerScanResultAsJson] = []

        # Register all JSON serializer functions defined in plugins
        for scan_command in ScanCommandEnum:
            scan_command.get_implementation_cls().cli_connector_cls.register_json_serializer_functions()

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
        self._server_scan_results.append(_ServerScanResultAsJson.from_server_scan_result(server_scan_result))

    def scans_completed(self, total_scan_time: float) -> None:
        final_json_output = _SslyzeOutputAsJson(
            server_scan_results=self._server_scan_results,
            server_connectivity_errors=self._server_connectivity_errors,
            total_scan_time=total_scan_time,
        )
        final_json_output_as_dict = asdict(final_json_output)
        json_out = json.dumps(
            final_json_output_as_dict, cls=_CustomJsonEncoder, sort_keys=True, indent=4, ensure_ascii=True
        )
        self._file_to.write(json_out)


# Make TracebackException pickable for dataclasses.asdict() to work on ScanCommandError
# It's hacky and not the right way to use copyreg, but works for our use case
def _traceback_to_str(traceback: TracebackException) -> str:
    exception_trace_as_str = ""
    for line in traceback.format(chain=False):
        exception_trace_as_str += line
    return exception_trace_as_str


copyreg.pickle(TracebackException, _traceback_to_str)  # type: ignore


# Setup our custom JSON serializer
JsonType = Union[bool, int, float, str, List[Any], Dict[str, Any]]


class _CustomJsonEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> JsonType:
        return object_to_json(obj)


_default_json_encoder = json.JSONEncoder()


# Using singledispatch allows plugins that return custom objects to extend the JSON serializing logic
@singledispatch
def object_to_json(obj: Any) -> JsonType:
    return _default_json_encoder.default(obj)


# Add the functions for serializing basic types
@object_to_json.register
def _enum(obj: Enum) -> JsonType:
    return obj.name


@object_to_json.register
def _set(obj: set) -> JsonType:
    return [object_to_json(value) for value in obj]


@object_to_json.register
def _path(obj: Path) -> JsonType:
    return str(obj)


@object_to_json.register
def _traceback(obj: TracebackException) -> JsonType:
    return _traceback_to_str(obj)


@object_to_json.register
def _datetime(obj: datetime) -> JsonType:
    return obj.isoformat()


@object_to_json.register
def _bytearray(obj: bytearray) -> JsonType:
    return b64encode(obj).decode("utf-8")
