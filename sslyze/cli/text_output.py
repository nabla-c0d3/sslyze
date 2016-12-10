



class TextOutput(object):

    SCAN_FORMAT = u'Scan Results For {0}:{1} - {2}:{1}'

    TITLE_FORMAT =  u' {title}\n {underline}\n'

    @classmethod
    def format_title(cls, title):
        return cls.TITLE_FORMAT.format(title=title.upper(), underline='-' * len(title))

    @classmethod
    def process_plugin_results(cls, server_info, result_list):
        target_result_str = u''

        for plugin_result in result_list:
            # Print the result of each separate command
            target_result_str += '\n'
            for line in plugin_result.as_text():
                target_result_str += line + '\n'

        scan_txt = cls.SCAN_FORMAT.format(server_info.hostname, str(server_info.port), server_info.ip_address)
        return cls.format_title(scan_txt) + target_result_str + '\n\n'

