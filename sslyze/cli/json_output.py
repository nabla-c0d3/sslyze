import json

from sslyze import PROJECT_URL, __version__
from sslyze.cli import CompletedServerScan
from sslyze.cli import FailedServerScan
from sslyze.cli.output_generator import OutputGenerator


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
            dict_result.pop("server_info", None)
            # Remove the plugin_command node
            plugin_command = dict_result.pop("plugin_command", None)
            if plugin_command in dict_command_result.keys():
                raise ValueError('Received duplicate result for command {}'.format(plugin_command))
            dict_command_result[plugin_command] = dict_result

        server_scan_dict['commands_results'] = dict_command_result
        self._json_dict['accepted_targets'].append(server_scan_dict)


    def scans_completed(self, total_scan_time):
        # type: (float) -> None
        self._json_dict['total_scan_time'] = total_scan_time
        json.dump(self._json_dict, self._file_to, default=self._object_to_json_dict, sort_keys=True, indent=4)


    @staticmethod
    def _object_to_json_dict(plugin_object):
        """Convert an object to a dictionnary suitable for the JSON output.
        """
        final_fict = {}
        for key, value in plugin_object.__dict__.iteritems():
            if not key.startswith('_'):
                # Remove private attributes
                final_fict[key] = value
        return final_fict
