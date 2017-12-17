# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import socket
import types
from enum import Enum
from typing import Optional, Tuple, Text, List
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
from tls_parser.record_protocol import TlsRecordTlsVersionBytes, TlsRecord, TlsRecordHeader
from tls_parser.exceptions import NotEnoughData
from tls_parser.handshake_protocol import TlsHandshakeRecord, TlsHandshakeTypeByte, TlsRsaClientKeyExchangeRecord
from tls_parser.parser import TlsRecordParser
from tls_parser.tls_version import TlsVersionEnum
from sslyze.utils.ssl_connection import SSLHandshakeRejected
from sslyze.utils.thread_pool import ThreadPool


class RobotScanCommand(PluginScanCommand):
    """Test the server(s) for the Return Of Bleichenbacher's Oracle Threat vulnerability.
    """

    @classmethod
    def get_cli_argument(cls):
        return 'robot'

    @classmethod
    def get_title(cls):
       return 'ROBOT'


class RobotPmsPaddingPayloadEnum(Enum):
    VALID = 0
    WRONG_FIRST_TWO_BYTES = 1
    WRONG_POSITION_00 = 2
    NO_00_IN_THE_MIDDLE = 3
    WRONG_VERSION_NUMBER = 4


class RobotClientKeyExchangePayloads(object):

    # From https://github.com/robotattackorg/robot-detect and testssl.sh
    _PAYLOADS_HEX = {
        RobotPmsPaddingPayloadEnum.VALID:                   "0002{pms_padding}00{tls_version}{pms}",
        RobotPmsPaddingPayloadEnum.WRONG_FIRST_TWO_BYTES:   "4117{pms_padding}00{tls_version}{pms}",
        RobotPmsPaddingPayloadEnum.WRONG_POSITION_00:       "0002{pms_padding}11{pms}0011",
        RobotPmsPaddingPayloadEnum.NO_00_IN_THE_MIDDLE:     "0002{pms_padding}111111{pms}",
        RobotPmsPaddingPayloadEnum.WRONG_VERSION_NUMBER:    "0002{pms_padding}000202{pms}",
    }

    _PMS_HEX = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"

    @classmethod
    def get_all(cls, tls_version, modulus, exponent):
        # type: (TlsVersionEnum, int, int) -> List[TlsRsaClientKeyExchangeRecord]
        """The core logic of the check is to send multiple Client Key Exchanges records with different, valid or
        invalid padding values for the pre_master_scret. Depending on how the server reacts to each payload, we can
        tell if it can be used as a decryption oracle or not.
        """
        test_cke_records = []

        # Generate the padding for the pre_master_scecret
        modulus_bit_size = int(math.ceil(math.log(modulus, 2)))
        modulus_byte_size = (modulus_bit_size + 7) // 8
        # pad_len is length in hex chars, so bytelen * 2
        pad_len = (modulus_byte_size - 48 - 3) * 2
        pms_padding = ("abcd" * (pad_len // 2 + 1))[:pad_len]

        tls_version_hex = binascii.b2a_hex(TlsRecordTlsVersionBytes[tls_version.name].value).decode('ascii')

        # The testing payloads
        for payload_enum, pms_with_padding_payload in cls._PAYLOADS_HEX.items():
            final_pms = pms_with_padding_payload.format(pms_padding=pms_padding, tls_version=tls_version_hex,
                                                        pms=cls._PMS_HEX)
            test_record = TlsRsaClientKeyExchangeRecord.from_parameters(
                tls_version, exponent, modulus, int(final_pms, 16)
            )
            test_cke_records.append(test_record)

        return test_cke_records


# This plugin is a re-implementation of/
class RobotPlugin(plugin_base.Plugin):
    """Test the server(s) for the Return Of Bleichenbacher's Oracle Threat vulnerability.
    """

    @classmethod
    def get_available_commands(cls):
        return [RobotScanCommand]

    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, RobotScanCommand) -> RobotScanResult
        # TODO(AD): Handle GCM Only ciphers
        # Use the discovered cipher suite too
        is_vulnerable_to_robot = False
        rsa_params = self._get_rsa_parameters(server_info)
        if rsa_params is None:
            pass
            # Not Vulnerable
            # TODO(AD): Display a better explanation
        else:
            rsa_modulus, rsa_exponent = rsa_params

            # Use threads to speed things up
            thread_pool = ThreadPool()
            for cke_record_payload in RobotClientKeyExchangePayloads.get_all(
                    server_info.highest_ssl_version_supported, rsa_modulus, rsa_exponent
            ):
                thread_pool.add_job((self._run_oracle, (server_info, cke_record_payload)))

            # Store the results as they come
            thread_pool.start(nb_threads=5)
            server_responses = []
            for completed_job in thread_pool.get_result():
                (job, response) = completed_job
                server_responses.append(response)

            for failed_job in thread_pool.get_error():
                # Should never happen when running Robot check as we catch all exceptions in the handshake
                (_, exception) = failed_job
                raise exception

            thread_pool.join()

            if len(set(server_responses)) > 1:
                # All server responses were NOT identical, server is vulnerable
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
    def _run_oracle(server_info, cke_record_payload):
        # Do a handshake which each record and keep track of what the server returned
        ssl_connection = server_info.get_preconfigured_ssl_connection()

        # Replace nassl.sslClient.do_handshake() with a ROBOT checking SSL handshake so that all the SSLyze
        # options (startTLS, proxy, etc.) still work
        ssl_connection.ssl_client.do_handshake = types.MethodType(do_handshake_with_robot,
                                                                  ssl_connection.ssl_client)
        # TODO(AD): Support GCM
        ssl_connection.ssl_client.set_cipher_list('RSA')

        # H4ck: we need to pass the CKE record to the handshake, we do that using an attribute
        ssl_connection.ssl_client._cke_record = cke_record_payload
        server_response = ''
        try:
            # Start the SSL handshake
            # TODO(AD): Remove print statements
            print('Sending Payload')
            ssl_connection.connect()
        except ServerResponseToRobot as e:
            # Should always be thrown
            server_response = e.server_response
            print('Received "{}"'.format(e.server_response))
        finally:
            ssl_connection.close()

        return server_response


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
