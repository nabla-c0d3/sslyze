# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import socket
import types
from typing import Optional, Tuple, Text
from xml.etree.ElementTree import Element

import binascii
import cryptography
import math
from cryptography.hazmat.backends import default_backend
from nassl._nassl import WantReadError
from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from tls_parser.alert_protocol import TlsAlertRecord
from tls_parser.record_protocol import TlsRecordTlsVersionBytes
from tls_parser.exceptions import NotEnoughData
from tls_parser.handshake_protocol import TlsHandshakeRecord, TlsHandshakeTypeByte, TlsRsaClientKeyExchangeRecord
from tls_parser.parser import TlsRecordParser
from tls_parser.tls_version import TlsVersionEnum
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
        # TODO(AD): Handle GCM Only ciphers
        is_vulnerable_to_robot = False
        rsa_params = self._get_rsa_parameters(server_info)
        if rsa_params is None:
            pass
            # Not Vulnerable
            # TODO(AD): Display a better explanation
        else:
            rsa_modulus, rsa_exponent = rsa_params
            server_responses = []
            for cke_record_payload in self._generate_test_cke_records(
                    server_info.highest_ssl_version_supported,rsa_modulus,rsa_exponent
            ):
                # Do a handshake which each record and keep track of what the server returned
                ssl_connection = server_info.get_preconfigured_ssl_connection()

                # Replace nassl.sslClient.do_handshake() with a ROBOT checking SSL handshake so that all the SSLyze
                # options (startTLS, proxy, etc.) still work
                ssl_connection.ssl_client.do_handshake = types.MethodType(do_handshake_with_robot,
                                                                          ssl_connection.ssl_client)

                # H4ck: we need the CKE record to the handshake, we do that using an attribute
                ssl_connection.ssl_client._cke_record = cke_record_payload

                try:
                    # Start the SSL handshake
                    # TODO(AD): Remove print statements
                    print('Sending Payload')
                    ssl_connection.connect()
                except ServerResponseToRobot as e:
                    # Should always be thrown
                    server_responses.append(e.server_response)
                    print('Received "{}"'.format(e.server_response))
                finally:
                    ssl_connection.close()

            if len(set(server_responses)) > 1:
                # All server responses were NOT identical, server it vulnerable
                is_vulnerable_to_robot = True

                # TODO(AD): Add logic to double check, like in robot-detect?

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

    @staticmethod
    def _generate_test_cke_records(tls_version, modulus, exponent):
        # type: (TlsVersionEnum, int, int) -> TlsRsaClientKeyExchangeRecord
        """The core logic of the check is to send multiple Client Key Exchanges records with different, valid or
        invalid padding values for the pre_master_scret. Depending on how the server reacts to each payload, we can
        tell if it can be used as a decryption oracle or not.
        """
        # From https://github.com/robotattackorg/robot-detect and testssl.sh
        test_cke_records = []

        # Generate the padding for the pre_master_scecret
        modulus_bit_size = int(math.ceil(math.log(modulus, 2)))
        modulus_byte_size = (modulus_bit_size + 7) // 8
        # pad_len is length in hex chars, so bytelen * 2
        pad_len = (modulus_byte_size - 48 - 3) * 2
        pms_padding = ("abcd" * (pad_len // 2 + 1))[:pad_len]

        # The pre_master_secret we will use
        pms = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"

        tls_version_hex = binascii.b2a_hex(TlsRecordTlsVersionBytes[tls_version.name].value).decode('ascii')

        # The testing payloads
        for pms_with_padding_payload in [
            # Generate padding - it should be of the form "00 02 <random> 00 <TLS version> <premaster secret>
            # Valid padding
            int("0002" + pms_padding + "00" + tls_version_hex + pms, 16),

            # Wrong first two bytes
            int("4117" + pms_padding + "00" + tls_version_hex + pms, 16),

            # 0x00 on a wrong position, also trigger older JSSE bug
            int("0002" + pms_padding + "11" + pms + "0011", 16),

            # No 0x00 in the middle
            int("0002" + pms_padding + "11" + "1111" + pms, 16),

            # Wrong version number (according to Klima / Pokorny / Rosa paper)
            int("0002" + pms_padding + "00" + "0202" + pms, 16)
        ]:
            test_record = TlsRsaClientKeyExchangeRecord.from_parameters(
                tls_version, exponent, modulus, pms_with_padding_payload
            )
            test_cke_records.append(test_record)

        return test_cke_records

    @staticmethod
    def _run_oracle(server_info, cke_record):
        ssl_connection = server_info.get_preconfigured_ssl_connection()
        ssl_connection.ssl_client.set_cipher_list('RSA')


class ServerResponseToRobot(Exception):
    def __init__(self, server_response):
        # type: (Text) -> None
        # Could be a TLS alert or some data, always as text so we can easily detect different responses
        self.server_response = server_response


def do_handshake_with_robot(self):
    """Modified do_handshake() to send a ROBOT payload and return the result.
    """
    try:
        # Start the handshake using nassl - will throw WantReadError right away
        self._ssl.do_handshake()
    except WantReadError:
        # Send the Client Hello
        len_to_read = self._network_bio.pending()
        while len_to_read:
            # Get the data from the SSL engine
            handshake_data_out = self._network_bio.read(len_to_read)
            # Send it to the peer
            self._sock.send(handshake_data_out)
            len_to_read = self._network_bio.pending()

    # Retrieve the server's response - directly read the underlying network socket
    # Retrieve data until we get to the ServerHelloDone
    # The server may send back a ServerHello, an Alert or a CertificateRequest first
    did_receive_hello_done = False
    remaining_bytes = b''
    while not did_receive_hello_done:
        try:
            tls_record, len_consumed = TlsRecordParser.parse_bytes(remaining_bytes)
            remaining_bytes = remaining_bytes[len_consumed::]
        except NotEnoughData:
            # Try to get more data
            raw_ssl_bytes = self._sock.recv(16381)
            if not raw_ssl_bytes:
                # No data?
                break

            remaining_bytes = remaining_bytes + raw_ssl_bytes
            continue

        if isinstance(tls_record, TlsHandshakeRecord):
            # Does the record contain a ServerDone message?
            for handshake_message in tls_record.subprotocol_messages:
                if handshake_message.handshake_type == TlsHandshakeTypeByte.SERVER_DONE:
                    did_receive_hello_done = True
                    break
            # If not, it could be a ServerHello, Certificate or a CertificateRequest if the server requires client auth
        elif isinstance(tls_record, TlsAlertRecord):
            # Server returned a TLS alert
            break
        else:
            raise ValueError('Unknown record? Type {}'.format(tls_record.header.type))

    if did_receive_hello_done:
        # Send a special Client Key Exchange Record as the payload
        self._sock.send(self._cke_record.to_bytes())

        # Return whatever the server sent back by raising an exception
        # The goal is to detect similar/different responses
        while True:
            try:
                tls_record, len_consumed = TlsRecordParser.parse_bytes(remaining_bytes)
                remaining_bytes = remaining_bytes[len_consumed::]
            except NotEnoughData:
                # Try to get more data
                try:
                    raw_ssl_bytes = self._sock.recv(16381)
                    if not raw_ssl_bytes:
                        # No data?
                        raise ServerResponseToRobot('No data')
                except socket.error as e:
                    # Server closed the connection after receiving the CCS payload
                    raise ServerResponseToRobot('socket.error {}'.format(str(e)))

                remaining_bytes = remaining_bytes + raw_ssl_bytes
                continue

            if isinstance(tls_record, TlsAlertRecord):
                raise ServerResponseToRobot('TLS Alert {} {}'.format(tls_record.alert_description,
                                                                     tls_record.alert_severity))
            else:
                break

        raise ServerResponseToRobot('Ok')


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
