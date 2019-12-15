from xml.etree.ElementTree import Element
from nassl.ssl_client import OpenSslVersionEnum, SslClient, OpenSslVerifyEnum
from nassl._nassl import OpenSSLError
import socket
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.server_connectivity_info import ServerConnectivityInfo
from typing import Type, List, Tuple
from enum import IntEnum


class TLSCurvesScanCommand(PluginScanCommand):

    @classmethod
    def get_cli_argument(cls) -> str:
        return "curves"

    @classmethod
    def get_title(cls) -> str:
        return "Scan for supported TLS curves"


class TLSVersionEnum(IntEnum):
    """SSL version constants.
    """

    TLSV1 = 3
    TLSV1_1 = 4
    TLSV1_2 = 5
    TLSV1_3 = 6


class TLSCurvesPlugin(plugin_base.Plugin):
    # TODO get full list of curves supported by OpenSSL
    CURVE_NAMES = ["X25519", "X448", "prime256v1", "secp384r1", "secp521r1", "secp256k1"]

    TLS_VERSIONS = [OpenSslVersionEnum.TLSV1, OpenSslVersionEnum.TLSV1_1, OpenSslVersionEnum.TLSV1_2,
                    OpenSslVersionEnum.TLSV1_3]

    @classmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        return [TLSCurvesScanCommand]

    def process_task(self, server_info: ServerConnectivityInfo, scan_command: PluginScanCommand) -> "PluginScanResult":
        if not isinstance(scan_command, TLSCurvesScanCommand):
            raise ValueError("Unexpected scan command")

        supported_curves = []
        i = 0
        for ssl_version in TLSVersionEnum:
            for curve in self.CURVE_NAMES:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((server_info.ip_address, server_info.port))

                ssl_client = SslClient(
                    ssl_version=ssl_version,
                    underlying_socket=sock,
                    ssl_verify=OpenSslVerifyEnum.NONE,  # TODO enable certificate verification
                )

                if ssl_version == OpenSslVersionEnum.TLSV1_3:
                    # TLSv1.3
                    ssl_client.set_cipher_list("")
                    ssl_client.set_ciphersuites(
                        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:"
                        "TLS_AES_128_CCM_8_SHA256")  # Source: https://tools.ietf.org/html/rfc8446#appendix-B.4
                else:
                    # TLSv1.2 and older
                    ssl_client.set_cipher_list("kEECDH")  # Source: https://linux.die.net/man/1/ciphers

                ssl_client.set1_groups_list(curve)

                try:
                    ssl_client.do_handshake()
                    # print(ssl_client.get_current_cipher_name())
                    supported_curves.append((curve, f"TLSv1.{i}"))
                except OpenSSLError:
                    pass
            i += 1

        return TLSCurvesScanResult(server_info, scan_command, supported_curves)


class TLSCurvesScanResult(PluginScanResult):

    def __init__(self, server_info: ServerConnectivityInfo, scan_command: TLSCurvesScanCommand,
                 supported_curves: List[Tuple[str, str]]) -> None:
        super().__init__(server_info, scan_command)
        self.supported_curves = supported_curves

    def as_text(self) -> List[str]:
        return self.supported_curves

    def as_xml(self) -> Element:
        xml_result = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())
        xml_result.append(self.supported_curves)
        return xml_result
