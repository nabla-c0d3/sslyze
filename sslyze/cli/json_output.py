import copyreg
import json
from dataclasses import asdict
from functools import singledispatch
from pathlib import Path
from traceback import TracebackException
from typing import Dict, Any, TextIO, Union, List

from enum import Enum
from sslyze import PROJECT_URL, __version__
from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.cli.output_generator import OutputGenerator
from sslyze.connection_helpers.errors import ConnectionToServerFailed
from sslyze.plugins.scan_commands import ScanCommandEnum
from sslyze.scanner import ServerScanResult
from sslyze.server_connectivity import ServerConnectivityInfo


# TODO: Crashes with certinfo
class JsonOutputGenerator(OutputGenerator):
    def __init__(self, file_to: TextIO) -> None:
        super().__init__(file_to)
        self._json_dict: Dict[str, Any] = {
            # TODO: validate names server_scan_results?
            "sslyze_version": __version__,
            "sslyze_url": PROJECT_URL,
            "invalid_servers": [],
            "accepted_servers": [],
        }

        # Register all JSON serializer functions defined in plugins
        for scan_command in ScanCommandEnum:
            scan_command.get_implementation_cls().cli_connector_cls.register_json_serializer_functions()

    def command_line_parsed(self, parsed_command_line: ParsedCommandLine) -> None:
        for bad_server_str in parsed_command_line.invalid_servers:
            self._json_dict["invalid_servers"].append({bad_server_str.server_string: bad_server_str.error_message})

    def server_connectivity_test_failed(self, connectivity_error: ConnectionToServerFailed) -> None:
        hostname = connectivity_error.server_location.hostname
        port = connectivity_error.server_location.port
        self._json_dict["invalid_servers"].append({f"{hostname}:{port}": connectivity_error.error_message})

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        pass

    def scans_started(self) -> None:
        pass

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        result_as_dict = asdict(server_scan_result)

        # The JSON encoder does not like dictionaries with enums as keys
        # Fix that by converting enum keys into their enum names
        for dict_field in ["scan_commands_results", "scan_commands_extra_arguments", "scan_commands_errors"]:
            result_as_dict[dict_field] = {
                scan_command.name: value for scan_command, value in result_as_dict[dict_field].items()
            }

        self._json_dict["accepted_servers"].append(result_as_dict)

    def scans_completed(self, total_scan_time: float) -> None:
        self._json_dict["total_scan_time"] = str(total_scan_time)
        json_out = json.dumps(self._json_dict, cls=_CustomJsonEncoder, sort_keys=True, indent=4, ensure_ascii=True)
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
