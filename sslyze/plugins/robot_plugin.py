# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from typing import Optional, Tuple
from xml.etree.ElementTree import Element

import cryptography
from cryptography.hazmat.backends import default_backend
from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo


from sslyze.utils.ssl_connection import SSLHandshakeRejected


class RobotScanCommand(PluginScanCommand):
    """Test the server(s) for the Return Of Bleichenbacher's Oracle Threat vulnerability.
    """

    @classmethod
    def get_cli_argument(cls):
        return 'robot'

    @classmethod
    def get_title(cls):
       return 'ROBOT'


# This plugin is a re-implementation of https://github.com/robotattackorg/robot-detect
class RobotPlugin(plugin_base.Plugin):
    """Test the server(s) for the Return Of Bleichenbacher's Oracle Threat vulnerability.
    """

    @classmethod
    def get_available_commands(cls):
        return [RobotScanCommand]

    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, RobotScanCommand) -> RobotScanResult
        rsa_params = self._get_rsa_parameters(server_info)
        if rsa_params is None:
            pass
            # Not Vulnerable
        else:
            rsa_n, rsa_e = rsa_params

        # TODO: Oracle testing
        is_vulnerable_to_robot = False
        return RobotScanResult(server_info, scan_command, is_vulnerable_to_robot)

    @staticmethod
    def _get_rsa_parameters(server_info):
        # type: (ServerConnectivityInfo) -> Optional[Tuple[int, int]]
        ssl_connection = server_info.get_preconfigured_ssl_connection()
        ssl_connection.ssl_client.set_cipher_list('RSA')
        parsed_cert = None
        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            certificate = ssl_connection.ssl_client.get_peer_certificate()
            parsed_cert = cryptography.x509.load_pem_x509_certificate(certificate.as_pem().encode('ascii'),
                                                                      backend=default_backend())
        except SSLHandshakeRejected as e:
            # Server does not support RSA cipher suites?
            pass
        except ClientCertificateRequested:  # The server asked for a client cert
            certificate = ssl_connection.ssl_client.get_peer_certificate()
            parsed_cert = cryptography.x509.load_pem_x509_certificate(certificate.as_pem().encode('ascii'),
                                                                      backend=default_backend())
        finally:
            ssl_connection.close()

        if parsed_cert:
            return parsed_cert.public_key().public_numbers().n, parsed_cert.public_key().public_numbers().e
        else:
            return None


class RobotScanResult(PluginScanResult):
    """The result of running a RobotScanCommand on a specific server.

    Attributes:
        is_vulnerable_to_robot (bool): True if the server is vulnerable to the ROBOT attack.
    """

    def __init__(self, server_info, scan_command, is_vulnerable_to_robot):
        # type: (ServerConnectivityInfo, RobotScanCommand, bool) -> None
        super(RobotScanResult, self).__init__(server_info, scan_command)
        self.is_vulnerable_to_robot = is_vulnerable_to_robot

    def as_text(self):
        robot_txt = 'VULNERABLE - Server is vulnerable to the ROBOT attack' \
            if self.is_vulnerable_to_robot \
            else 'OK - Not vulnerable to the ROBOT attack'

        return [self._format_title(self.scan_command.get_title()), self._format_field('', robot_txt)]

    def as_xml(self):
        xml_output = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())
        xml_output.append(Element('robot', isVulnerable=str(self.is_vulnerable_to_robot)))
        return xml_output
