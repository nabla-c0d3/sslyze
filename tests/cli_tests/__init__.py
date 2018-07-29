from xml.etree.ElementTree import Element

from sslyze.plugins.plugin_base import PluginScanCommand
from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.ssl_settings import TlsWrappedProtocolEnum


class MockServerConnectivityInfo(ServerConnectivityInfo):
    def __init__(self, client_auth_requirement=None, http_tunneling_settings=None):
        self.hostname = 'unicödeéè.com'
        self.port = 443
        self.ip_address = '2001:0:9d38:6abd:1c85:1b5b:3fb2:4231'
        self.client_auth_requirement = client_auth_requirement
        self.tls_wrapped_protocol = TlsWrappedProtocolEnum.HTTPS

        self.http_tunneling_settings = http_tunneling_settings
        if http_tunneling_settings:
            # When scanning through a proxy, we do not know the final server's IP address
            self.ip_address = None


class MockServerConnectivityTester(ServerConnectivityTester):
    def __init__(self, hostname='unicödeéè.com'):
        self.hostname = hostname
        self.port = 443
        self.ip_address = '2001:0:9d38:6abd:1c85:1b5b:3fb2:4231'
        self.tls_wrapped_protocol = TlsWrappedProtocolEnum.HTTPS


class MockPluginScanCommandOne(PluginScanCommand):

    @classmethod
    def get_title(cls) -> str:
        return 'Plugin 1'

    @classmethod
    def get_cli_argument(cls):
        return 'plugin1'


class MockPluginScanCommandTwo(PluginScanCommand):

    @classmethod
    def get_title(cls) -> str:
        return 'Plugin 2'

    @classmethod
    def get_cli_argument(cls):
        return 'plugin2'


class MockPluginScanResult(PluginScanResult):
    def __init__(self, server_info, scan_command, text_output, xml_output):
        super().__init__(server_info, scan_command)
        self.text_output = text_output
        self.xml_output = xml_output
        self.scan_command = scan_command

    def as_xml(self):
        return self.xml_output

    def as_text(self):
        return [self.text_output]


class MockCommandLineValues:
    def __init__(self):
        # Tests don't really use right now
        pass
