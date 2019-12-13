from xml.etree.ElementTree import Element
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.server_connectivity_info import ServerConnectivityInfo
from typing import Type, List


class TLSCurvesScanCommand(PluginScanCommand):

    @classmethod
    def get_cli_argument(cls) -> str:
        return "curves"

    @classmethod
    def get_title(cls) -> str:
        return "Scan for supported TLS curves"


class TLSCurvesPlugin(plugin_base.Plugin):

    @classmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        return [TLSCurvesScanCommand]

    def process_task(self, server_info: ServerConnectivityInfo, scan_command: PluginScanCommand) -> "PluginScanResult":
        if not isinstance(scan_command, TLSCurvesScanCommand):
            raise ValueError("Unexpected scan command")

        return TLSCurvesScanResult(server_info, scan_command, ["test1", "test2"])


class TLSCurvesScanResult(PluginScanResult):

    def __init__(self, server_info: ServerConnectivityInfo, scan_command: TLSCurvesScanCommand,
                 supported_curves: List[str]) -> None:
        super().__init__(server_info, scan_command)
        self.supported_curves = supported_curves

    def as_text(self) -> List[str]:
        return self.supported_curves

    def as_xml(self) -> Element:
        xml_result = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())
        xml_result.append(self.supported_curves)
        return xml_result
