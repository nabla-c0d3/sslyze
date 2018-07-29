import json
from typing import Dict, Any, TextIO, Type, Set, Union, List

from cryptography.hazmat.backends.openssl import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from enum import Enum
from sslyze import PROJECT_URL, __version__
from sslyze.cli import CompletedServerScan
from sslyze.cli.command_line_parser import ServerStringParsingError
from sslyze.cli.output_generator import OutputGenerator
from sslyze.plugins.plugin_base import Plugin
from sslyze.plugins.utils.certificate_utils import CertificateUtils
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.server_connectivity_tester import ServerConnectivityError


class JsonOutputGenerator(OutputGenerator):

    def __init__(self, file_to: TextIO) -> None:
        super().__init__(file_to)
        self._json_dict: Dict[str, Any] = {
            'sslyze_version': __version__,
            'sslyze_url': PROJECT_URL
        }

    def command_line_parsed(
            self,
            available_plugins: Set[Type[Plugin]],
            args_command_list: Any,
            malformed_servers: List[ServerStringParsingError]
    ) -> None:
        self._json_dict.update({'invalid_targets': [], 'accepted_targets': []})

        for bad_server_str in malformed_servers:
            self._json_dict['invalid_targets'].append({bad_server_str.server_string: bad_server_str.error_message})

    def server_connectivity_test_failed(self, connectivity_error: ServerConnectivityError) -> None:
        server_info = connectivity_error.server_info
        self._json_dict['invalid_targets'].append({
            '{}:{}'.format(server_info.hostname, server_info.port): connectivity_error.error_message
        })

    def server_connectivity_test_succeeded(self, server_connectivity_info: ServerConnectivityInfo) -> None:
        pass

    def scans_started(self) -> None:
        pass

    def server_scan_completed(self, server_scan_result: CompletedServerScan) -> None:
        server_scan_dict = {'server_info': server_scan_result.server_info.__dict__.copy()}
        for key, value in server_scan_dict['server_info'].items():
            server_scan_dict['server_info'][key] = _object_to_json_dict(value)

        dict_command_result: Dict[str, Dict[str, Any]] = {}
        for plugin_result in server_scan_result.plugin_result_list:
            dict_result = plugin_result.__dict__.copy()
            # Remove the server_info node
            dict_result.pop('server_info', None)

            # Remove the scan_command node
            scan_command = dict_result.pop('scan_command', None)

            if scan_command.get_cli_argument() in dict_command_result.keys():
                raise ValueError('Received duplicate result for command {}'.format(scan_command))

            for key, value in dict_result.items():
                dict_result[key] = _object_to_json_dict(value)

            dict_command_result[scan_command.get_cli_argument()] = dict_result

        server_scan_dict['commands_results'] = dict_command_result
        self._json_dict['accepted_targets'].append(server_scan_dict)

    def scans_completed(self, total_scan_time: float) -> None:
        self._json_dict['total_scan_time'] = str(total_scan_time)
        json_out = json.dumps(
            self._json_dict, default=_object_to_json_dict, sort_keys=True, indent=4, ensure_ascii=True
        )
        self._file_to.write(json_out)


def _object_to_json_dict(obj: Any) -> Union[bool, int, float, str, Dict[str, Any]]:
    """Convert an object to a dictionary suitable for the JSON output.
    """
    if isinstance(obj, Enum):
        # Properly serialize Enums (such as OpenSslVersionEnum)
        result = obj.name

    elif isinstance(obj, x509._Certificate):
        # Properly serialize certificates
        certificate = obj
        result = {  # type: ignore
            # Add general info
            'as_pem': obj.public_bytes(Encoding.PEM).decode('ascii'),
            'hpkp_pin': CertificateUtils.get_hpkp_pin(obj),

            # Add some of the fields of the cert
            'subject': CertificateUtils.get_name_as_text(certificate.subject),
            'issuer': CertificateUtils.get_name_as_text(certificate.issuer),
            'serialNumber': str(certificate.serial_number),
            'notBefore': certificate.not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
            'notAfter': certificate.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
            'signatureAlgorithm': certificate.signature_hash_algorithm.name,
            'publicKey': {
                'algorithm': CertificateUtils.get_public_key_type(certificate)
            },
        }

        dns_alt_names = CertificateUtils.get_dns_subject_alternative_names(certificate)
        if dns_alt_names:
            result['subjectAlternativeName'] = {'DNS': dns_alt_names}  # type: ignore

        # Add some info about the public key
        public_key = certificate.public_key()
        if isinstance(public_key, EllipticCurvePublicKey):
            result['publicKey']['size'] = str(public_key.curve.key_size)  # type: ignore
            result['publicKey']['curve'] = public_key.curve.name  # type: ignore
        else:
            result['publicKey']['size'] = str(public_key.key_size)
            result['publicKey']['exponent'] = str(public_key.public_numbers().e)

    elif isinstance(obj, object):
        # Some objects (like str) don't have a __dict__
        if hasattr(obj, '__dict__'):
            result = {}
            for key, value in obj.__dict__.items():
                # Remove private attributes
                if key.startswith('_'):
                    continue

                result[key] = _object_to_json_dict(value)
        else:
            # Simple object like a bool
            result = obj

    else:
        raise TypeError('Unknown type: {}'.format(repr(obj)))

    return result
