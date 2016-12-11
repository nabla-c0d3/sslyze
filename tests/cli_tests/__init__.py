# coding=utf-8
from xml.etree.ElementTree import Element

from sslyze.ssl_settings import TlsWrappedProtocolEnum


class MockServerConnectivityInfo(object):
    def __init__(self, client_auth_requirement=None, http_tunneling_settings=None):
        self.hostname = u'unicödeéè.com'
        self.port = 443
        self.ip_address = '2001:0:9d38:6abd:1c85:1b5b:3fb2:4231'
        self.client_auth_requirement = client_auth_requirement
        self.tls_wrapped_protocol = TlsWrappedProtocolEnum.HTTPS
        self.http_tunneling_settings = http_tunneling_settings


class MockPluginResult(object):
    def __init__(self, plugin_command, text_output, xml_output):
        # type: (str, unicode, Element) -> None
        self.text_output = text_output
        self.xml_output = xml_output
        self.plugin_command = plugin_command

    def as_xml(self):
        return self.xml_output

    def as_text(self):
        return [self.text_output]


class MockCommandLineValues(object):
    def __init__(self):
        self.timeout = 2
        self.nb_retries = 5
