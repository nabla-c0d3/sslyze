# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import json
from enum import Enum
from sslyze import PROJECT_URL, __version__
from sslyze.cli import CompletedServerScan
from sslyze.cli import FailedServerScan
from sslyze.cli.output_generator import OutputGenerator
from sslyze.utils.python_compatibility import IS_PYTHON_2


class JsonOutputGenerator(OutputGenerator):

    def __init__(self, file_to):
        super(JsonOutputGenerator, self).__init__(file_to)
        self._json_dict = {'sslyze_version': __version__,
                           'sslyze_url': PROJECT_URL}

    def command_line_parsed(self, available_plugins, args_command_list):
        self._json_dict.update({'network_timeout': str(args_command_list.timeout),
                                'network_max_retries': str(args_command_list.nb_retries),
                                'invalid_targets': [],
                                'accepted_targets': []})

    def server_connectivity_test_failed(self, failed_scan):
        # type: (FailedServerScan) -> None
        self._json_dict['invalid_targets'].append({failed_scan.server_string: failed_scan.error_message})

    def server_connectivity_test_succeeded(self, server_connectivity_info):
        pass

    def scans_started(self):
        pass

    def server_scan_completed(self, server_scan_result):
        # type: (CompletedServerScan) -> None
        server_scan_dict = {'server_info': server_scan_result.server_info.__dict__}

        dict_command_result = {}
        for plugin_result in server_scan_result.plugin_result_list:
            dict_result = plugin_result.__dict__.copy()
            # Remove the server_info node
            dict_result.pop('server_info', None)

            # Remove the scan_command node
            scan_command = dict_result.pop('scan_command', None)

            if scan_command.get_cli_argument() in dict_command_result.keys():
                raise ValueError('Received duplicate result for command {}'.format(scan_command))
            dict_command_result[scan_command.get_cli_argument()] = dict_result

        server_scan_dict['commands_results'] = dict_command_result
        self._json_dict['accepted_targets'].append(server_scan_dict)

    def scans_completed(self, total_scan_time):
        # type: (float) -> None
        self._json_dict['total_scan_time'] = total_scan_time
        json_out = json.dumps(self._json_dict, default=self._object_to_json_dict, sort_keys=True, indent=4,
                              ensure_ascii=True)
        if IS_PYTHON_2:
            json_out = unicode(json_out)
        self._file_to.write(json_out)

    @staticmethod
    def _object_to_json_dict(obj):
        """Convert an object to a dictionary suitable for the JSON output.
        """
        if isinstance(obj, Enum):
            # Properly serialize Enums (such as OpenSslVersionEnum)
            result = obj.name
        elif isinstance(obj, object):
            result = {}
            for key, value in obj.__dict__.items():
                # Remove private attributes
                if key.startswith('_'):
                    continue

                result[key] = value
        else:
            raise TypeError('Unknown type: {}'.format(repr(obj)))

        return result
