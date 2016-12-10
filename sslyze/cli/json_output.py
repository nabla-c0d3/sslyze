


class JsonOutput(object):

    @classmethod
    def process_plugin_results(cls, server_info, result_list):
        dict_final = {'server_info': server_info.__dict__}
        dict_command_result = {}
        for plugin_result in result_list:
            dict_result = plugin_result.__dict__
            # Remove the server_info node
            dict_result.pop("server_info", None)
            # Remove the plugin_command node
            plugin_command = dict_result.pop("plugin_command", None)
            dict_command_result[plugin_command] = dict_result

        dict_final['commands_results'] = dict_command_result

        return dict_final

    @classmethod
    def object_to_json_dict(cls, plugin_object):
        """Convert an object to a dictionnary suitable for the JSON output.
        """
        final_fict = {}
        for key, value in plugin_object.__dict__.iteritems():
            if not key.startswith('_'):
                # Remove private attributes
                final_fict[key] = value
        return final_fict
