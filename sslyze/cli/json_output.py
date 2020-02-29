import copyreg
import json
from dataclasses import asdict
from pathlib import Path
from traceback import TracebackException
from typing import Dict, Any, TextIO, Union, Set

from cryptography.hazmat.backends.openssl import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ObjectIdentifier
from enum import Enum
from sslyze import PROJECT_URL, __version__
from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.cli.output_generator import OutputGenerator
from sslyze.connection_helpers.errors import ConnectionToServerFailed
from sslyze.plugins.utils.certificate_utils import CertificateUtils
from sslyze.scanner import ServerScanResult
from sslyze.server_connectivity import ServerConnectivityInfo


# Make TracebackException pickable for dataclasses.asdict() to work on ScanCommandError
def _traceback_to_str(traceback: TracebackException) -> str:
    exception_trace_as_str = ""
    for line in traceback.format(chain=False):
        exception_trace_as_str += line
    return exception_trace_as_str


copyreg.pickle(TracebackException, _traceback_to_str)


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
        for dict_field in [
            "scan_commands_results", "scan_commands_extra_arguments", "scan_commands_errors"
        ]:
            result_as_dict[dict_field] = {
                scan_command.name: value
                for scan_command, value in result_as_dict[dict_field].items()
            }

        self._json_dict["accepted_servers"].append(result_as_dict)

    def scans_completed(self, total_scan_time: float) -> None:
        self._json_dict["total_scan_time"] = str(total_scan_time)
        json_out = json.dumps(self._json_dict, cls=_CustomJsonEncoder, sort_keys=True, indent=4, ensure_ascii=True)
        self._file_to.write(json_out)


# TODO(AD) Remove and move to plugins
class _CustomJsonEncoder(json.JSONEncoder):

    def default(self, obj: Any) -> Union[bool, int, float, str, Dict[str, Any]]:
        result: Union[bool, int, float, str, Dict[str, Any]]

        if isinstance(obj, Enum):
            result = obj.name

        elif isinstance(obj, Set):
            result = [self.default(value) for value in obj]

        elif isinstance(obj, Path):
            result = str(obj)

        elif isinstance(obj, TracebackException):
            result = _traceback_to_str(obj)

        elif isinstance(obj, ObjectIdentifier):
            result = obj.dotted_string

        elif isinstance(obj, x509._Certificate):
            certificate = obj
            result = {
                # Add general info
                "as_pem": obj.public_bytes(Encoding.PEM).decode("ascii"),
                "hpkp_pin": CertificateUtils.get_hpkp_pin(obj),
                # Add some of the fields of the cert
                "subject": CertificateUtils.get_name_as_text(certificate.subject),
                "issuer": CertificateUtils.get_name_as_text(certificate.issuer),
                "serialNumber": str(certificate.serial_number),
                "notBefore": certificate.not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
                "notAfter": certificate.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
                "signatureAlgorithm": certificate.signature_hash_algorithm.name,
                "publicKey": {"algorithm": CertificateUtils.get_public_key_type(certificate)},
            }

            dns_alt_names = CertificateUtils.get_dns_subject_alternative_names(certificate)
            if dns_alt_names:
                result["subjectAlternativeName"] = {"DNS": dns_alt_names}  # type: ignore

            # Add some info about the public key
            public_key = certificate.public_key()
            if isinstance(public_key, EllipticCurvePublicKey):
                result["publicKey"]["size"] = str(public_key.curve.key_size)  # type: ignore
                result["publicKey"]["curve"] = public_key.curve.name  # type: ignore
            else:
                result["publicKey"]["size"] = str(public_key.key_size)
                result["publicKey"]["exponent"] = str(public_key.public_numbers().e)

        else:
            result = super().default(obj)

        return result
