# coding=utf-8

class MockServerConnectivityInfo(object):
    def __init__(self, client_auth_requirement=None):
        self.hostname = u'unicödeéè.com'
        self.port = 443
        self.ip_address = '2001:0:9d38:6abd:1c85:1b5b:3fb2:4231'
        self.client_auth_requirement = client_auth_requirement


class MockPluginResult(object):
    def __init__(self, plugin_command, text_output):
        self.text_output = text_output
        self.plugin_command = plugin_command

    def as_xml(self):
        pass

    def as_text(self):
        return [self.text_output]