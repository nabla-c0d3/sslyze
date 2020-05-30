import copyreg
from base64 import b64encode
from datetime import datetime
from functools import singledispatch
from pathlib import Path
from traceback import TracebackException

import json
from enum import Enum
from sslyze.plugins.scan_commands import ScanCommandsRepository
from typing import Dict, Any, Union, List, Callable


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


def _enum_to_json(obj: Enum) -> JsonType:
    return obj.name


def _set_to_json(obj: set) -> JsonType:
    return list(obj)


def _path_to_json(obj: Path) -> JsonType:
    return str(obj)


def _traceback_to_json(obj: TracebackException) -> JsonType:
    return _traceback_to_str(obj)


def _datetime_to_json(obj: datetime) -> JsonType:
    return obj.isoformat()


def _bytearray_to_json(obj: bytearray) -> JsonType:
    return b64encode(obj).decode("utf-8")


JsonSerializerFunction = Callable[[Any], "JsonType"]


class JsonEncoder(json.JSONEncoder):
    """Special JSON encoder that can serialize any ServerScanResult returned by SSLyze.

    A ServerScanResult can be serialized to JSON using the following code:

    >>> from dataclasses import asdict
    >>> import json
    >>> import sslyze
    >>>
    >>> scanner = sslyze.Scanner()
    >>> # Queue some ServerScanRequest... and then retrieve the results...
    >>> for server_scan_result in scanner.get_results():
    >>>     server_scan_result_as_json = json.dumps(asdict(server_scan_result), cls=sslyze.JsonEncoder)
    """

    def __init__(  # type: ignore
        self,
        *,
        skipkeys=False,
        ensure_ascii=True,
        check_circular=True,
        allow_nan=True,
        sort_keys=False,
        indent=None,
        separators=None,
        default=None,
    ):
        super().__init__(
            skipkeys=skipkeys,
            ensure_ascii=ensure_ascii,
            check_circular=check_circular,
            allow_nan=allow_nan,
            sort_keys=sort_keys,
            indent=indent,
            separators=separators,
            default=default,
        )

        self._default_json_encoder = json.JSONEncoder()

        # Using singledispatch allows plugins that return custom objects to extend the JSON serializing logic
        @singledispatch
        def object_to_json(obj: Any) -> JsonType:
            # Assume a default Python type if this function gets called instead of all the registered functions
            return self._default_json_encoder.encode(obj)

        self._json_dispatch_function = object_to_json

        # Register all JSON serializer functions for basic types
        self._json_dispatch_function.register(_enum_to_json)
        self._json_dispatch_function.register(_set_to_json)
        self._json_dispatch_function.register(_path_to_json)
        self._json_dispatch_function.register(_traceback_to_json)
        self._json_dispatch_function.register(_datetime_to_json)
        self._json_dispatch_function.register(_bytearray_to_json)

        # Register all JSON serializer functions defined in plugins
        for scan_command in ScanCommandsRepository.get_all_scan_commands():
            cli_connector_cls = ScanCommandsRepository.get_implementation_cls(scan_command).cli_connector_cls
            for json_serializer_function in cli_connector_cls.get_json_serializer_functions():
                self._json_dispatch_function.register(json_serializer_function)

    def default(self, obj: Any) -> JsonType:
        """Called by json.dumps() to serialize an object to JSON.
        """
        return self._json_dispatch_function(obj)
