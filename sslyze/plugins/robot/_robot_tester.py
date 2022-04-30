import socket
import types
from enum import Enum
from typing import Optional, List, Dict

import binascii
import math
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.x509 import load_pem_x509_certificate
from nassl._nassl import WantReadError
from nassl.ssl_client import ClientCertificateRequested
from tls_parser.change_cipher_spec_protocol import TlsChangeCipherSpecRecord

from tls_parser.alert_protocol import TlsAlertRecord
from tls_parser.record_protocol import TlsRecordTlsVersionBytes
from tls_parser.exceptions import NotEnoughData
from tls_parser.handshake_protocol import TlsHandshakeRecord, TlsHandshakeTypeByte, TlsRsaClientKeyExchangeRecord
from tls_parser.parser import TlsRecordParser

import tls_parser.tls_version

from sslyze.errors import ServerRejectedTlsHandshake
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum, ClientAuthRequirementEnum


class RobotScanResultEnum(str, Enum):
    """The result of attempting exploit the ROBOT issue on the server.

    Attributes:
        VULNERABLE_WEAK_ORACLE: The server is vulnerable but the attack would take too long.
        VULNERABLE_STRONG_ORACLE: The server is vulnerable and real attacks are feasible.
        NOT_VULNERABLE_NO_ORACLE: The server supports RSA cipher suites but does not act as an oracle.
        NOT_VULNERABLE_RSA_NOT_SUPPORTED: The server does not supports RSA cipher suites.
        UNKNOWN_INCONSISTENT_RESULTS: Could not determine whether the server is vulnerable or not.
    """

    VULNERABLE_WEAK_ORACLE = "VULNERABLE_WEAK_ORACLE"
    VULNERABLE_STRONG_ORACLE = "VULNERABLE_STRONG_ORACLE"
    NOT_VULNERABLE_NO_ORACLE = "NOT_VULNERABLE_NO_ORACLE"
    NOT_VULNERABLE_RSA_NOT_SUPPORTED = "NOT_VULNERABLE_RSA_NOT_SUPPORTED"
    UNKNOWN_INCONSISTENT_RESULTS = "UNKNOWN_INCONSISTENT_RESULTS"


class RobotPmsPaddingPayloadEnum(Enum):
    VALID = 0
    WRONG_FIRST_TWO_BYTES = 1
    WRONG_POSITION_00 = 2
    NO_00_IN_THE_MIDDLE = 3
    WRONG_VERSION_NUMBER = 4


class _RobotTlsRecordPayloads:

    # From https://github.com/robotattackorg/robot-detect and testssl.sh
    # The high level idea of an oracle attack is to send several payloads that are slightly wrong, in different ways,
    # hoping that the server is going to give a different response (a TLS alert, a connection reset, no data, etc.) for
    # each payload
    _CKE_PAYLOADS_HEX = {
        RobotPmsPaddingPayloadEnum.VALID: "0002{pms_padding}00{tls_version}{pms}",  # noqa: E241
        RobotPmsPaddingPayloadEnum.WRONG_FIRST_TWO_BYTES: "4117{pms_padding}00{tls_version}{pms}",  # noqa: E241
        RobotPmsPaddingPayloadEnum.WRONG_POSITION_00: "0002{pms_padding}11{pms}0011",  # noqa: E241
        RobotPmsPaddingPayloadEnum.NO_00_IN_THE_MIDDLE: "0002{pms_padding}111111{pms}",  # noqa: E241
        RobotPmsPaddingPayloadEnum.WRONG_VERSION_NUMBER: "0002{pms_padding}000202{pms}",  # noqa: E241
    }

    _PMS_HEX = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"

    @classmethod
    def get_client_key_exchange_record(
        cls,
        robot_payload_enum: RobotPmsPaddingPayloadEnum,
        tls_version: tls_parser.tls_version.TlsVersionEnum,
        modulus: int,
        exponent: int,
    ) -> TlsRsaClientKeyExchangeRecord:
        """A client key exchange record with a hardcoded pre_master_secret, and a valid or invalid padding."""
        pms_padding = cls._compute_pms_padding(modulus)
        tls_version_hex = binascii.b2a_hex(TlsRecordTlsVersionBytes[tls_version.name].value).decode("ascii")

        pms_with_padding_payload = cls._CKE_PAYLOADS_HEX[robot_payload_enum]
        final_pms = pms_with_padding_payload.format(
            pms_padding=pms_padding, tls_version=tls_version_hex, pms=cls._PMS_HEX
        )
        cke_robot_record = TlsRsaClientKeyExchangeRecord.from_parameters(
            tls_version, exponent, modulus, int(final_pms, 16)
        )
        return cke_robot_record

    @staticmethod
    def _compute_pms_padding(modulus: int) -> str:
        # Generate the padding for the pre_master_scecret
        modulus_bit_size = int(math.ceil(math.log(modulus, 2)))
        modulus_byte_size = (modulus_bit_size + 7) // 8
        # pad_len is length in hex chars, so bytelen * 2
        pad_len = (modulus_byte_size - 48 - 3) * 2
        pms_padding_hex = ("abcd" * (pad_len // 2 + 1))[:pad_len]
        return pms_padding_hex

    # Encrypted Finished record corresponding to the PMS below and the ch_def client hello in the ROBOT poc script
    _FINISHED_RECORD = bytearray.fromhex(
        "005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40"
        "d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0"
    )

    @classmethod
    def get_finished_record_bytes(cls, tls_version: tls_parser.tls_version.TlsVersionEnum) -> bytes:
        """The Finished TLS record corresponding to the hardcoded PMS used in the Client Key Exchange record."""
        # TODO(AD): The ROBOT poc script uses the same Finished record for all possible client hello (default, GCM,
        # etc.); as the Finished record contains a hashes of all previous records, it will be wrong and will cause
        # servers to send a TLS Alert 20
        # Here just like in the poc script, the Finished message does not match the Client Hello we sent
        return b"\x16" + TlsRecordTlsVersionBytes[tls_version.name].value + cls._FINISHED_RECORD


class RobotServerResponsesAnalyzer:
    def __init__(self, payload_responses: Dict[RobotPmsPaddingPayloadEnum, List[str]], attempts_count: int) -> None:
        # A mapping of a ROBOT payload enum -> a list of two server responses as text
        for server_responses in payload_responses.values():
            if len(server_responses) != attempts_count:
                raise ValueError()
        self._payload_responses = payload_responses
        self._attempts_count = attempts_count

    def compute_result_enum(self) -> RobotScanResultEnum:
        """Look at the server's response to each ROBOT payload and return the conclusion of the analysis."""
        # Ensure the results were consistent
        for payload_enum, server_responses in self._payload_responses.items():
            # We ran the check a number of times per payload and the responses should be the same
            if len(set(server_responses)) != 1:
                return RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS

        # Check if the server acts as an oracle by checking if the server replied differently to the payloads
        if len(set([server_responses[0] for server_responses in self._payload_responses.values()])) == 1:
            # All server responses were identical - no oracle
            return RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE

        # All server responses were NOT identical, server is vulnerable
        # Check to see if it is a weak oracle
        response_1 = self._payload_responses[RobotPmsPaddingPayloadEnum.WRONG_FIRST_TWO_BYTES][0]
        response_2 = self._payload_responses[RobotPmsPaddingPayloadEnum.WRONG_POSITION_00][0]
        response_3 = self._payload_responses[RobotPmsPaddingPayloadEnum.NO_00_IN_THE_MIDDLE][0]

        # From the original script:
        # If the response to the invalid PKCS#1 request (oracle_bad1) is equal to both
        # requests starting with 0002, we have a weak oracle. This is because the only
        # case where we can distinguish valid from invalid requests is when we send
        # correctly formatted PKCS#1 message with 0x00 on a correct position. This
        # makes our oracle weak
        if response_1 == response_2 == response_3:
            return RobotScanResultEnum.VULNERABLE_WEAK_ORACLE
        else:
            return RobotScanResultEnum.VULNERABLE_STRONG_ORACLE


class ServerDoesNotSupportRsa(Exception):
    pass


def test_robot(server_info: ServerConnectivityInfo) -> Dict[RobotPmsPaddingPayloadEnum, str]:
    # Try with TLS 1.2 even if the server supports TLS 1.3 or higher
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        tls_version_to_use = TlsVersionEnum.TLS_1_2
    else:
        tls_version_to_use = server_info.tls_probing_result.highest_tls_version_supported

    rsa_params = None
    # With TLS 1.2 some servers are only vulnerable when using the GCM cipher suites - try them first
    if tls_version_to_use == TlsVersionEnum.TLS_1_2:
        cipher_string = "AES128-GCM-SHA256:AES256-GCM-SHA384"
        rsa_params = _get_rsa_parameters(server_info, tls_version_to_use, cipher_string)

    if rsa_params is None:
        # The attempts with GCM TLS 1.2 RSA cipher suites failed - try the normal RSA cipher suites
        cipher_string = "RSA"
        rsa_params = _get_rsa_parameters(server_info, tls_version_to_use, cipher_string)

    if rsa_params is None:
        # Could not connect to the server using RSA - not vulnerable
        raise ServerDoesNotSupportRsa()

    rsa_modulus = rsa_params.n
    rsa_exponent = rsa_params.e

    # On the first attempt, finish the TLS handshake after sending the Robot payload
    robot_should_complete_handshake = True
    server_responses_per_robot_payloads = _run_oracle_detection(
        server_info, tls_version_to_use, cipher_string, rsa_modulus, rsa_exponent, robot_should_complete_handshake
    )
    return server_responses_per_robot_payloads

    # TODO(AD): The following section was taken from the original ROBOT poc script but makes the scans really slow as it
    # waits for server timeouts
    robot_result_enum = RobotServerResponsesAnalyzer(
        {payload_enum: [response] for payload_enum, response in server_responses_per_robot_payloads.items()}, 1
    ).compute_result_enum()

    if robot_result_enum == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE:
        # Try again but this time do not finish the TLS handshake - for some servers it will reveal an oracle
        robot_should_complete_handshake = False
        server_responses_per_robot_payloads = _run_oracle_detection(
            server_info, tls_version_to_use, cipher_string, rsa_modulus, rsa_exponent, robot_should_complete_handshake
        )

    return server_responses_per_robot_payloads


def _run_oracle_detection(
    server_info: ServerConnectivityInfo,
    tls_version_to_use: TlsVersionEnum,
    cipher_string: str,
    rsa_modulus: int,
    rsa_exponent: int,
    should_complete_handshake: bool,
) -> Dict[RobotPmsPaddingPayloadEnum, str]:
    server_responses_per_robot_payloads: Dict[RobotPmsPaddingPayloadEnum, str] = {}
    for payload_enum in RobotPmsPaddingPayloadEnum:
        server_response = _send_robot_payload(
            server_info,
            tls_version_to_use,
            cipher_string,
            payload_enum,
            should_complete_handshake,
            rsa_modulus,
            rsa_exponent,
        )

        server_responses_per_robot_payloads[payload_enum] = server_response
    return server_responses_per_robot_payloads


def _get_rsa_parameters(
    server_info: ServerConnectivityInfo, tls_version: TlsVersionEnum, openssl_cipher_string: str
) -> Optional[RSAPublicNumbers]:
    ssl_connection = server_info.get_preconfigured_tls_connection(
        override_tls_version=tls_version,
        should_use_legacy_openssl=True,
    )
    ssl_connection.ssl_client.set_cipher_list(openssl_cipher_string)
    parsed_cert = None
    try:
        # Perform the SSL handshake
        ssl_connection.connect()
        cert_as_pem = ssl_connection.ssl_client.get_received_chain()[0]
        parsed_cert = load_pem_x509_certificate(cert_as_pem.encode("ascii"), backend=default_backend())
    except ServerRejectedTlsHandshake:
        # Server does not support RSA cipher suites?
        pass
    except ClientCertificateRequested:
        # AD: The server asked for a client cert. We could still retrieve the server certificate, but it is unclear
        # to me if the ROBOT check is supposed to work even if we do not provide a client cert. My guess is that
        # it should not work since it requires completing a full handshake, which we can't without a client cert.
        # Hence, propagate the error to make the check fail.
        raise
    finally:
        ssl_connection.close()

    if parsed_cert:
        public_key = parsed_cert.public_key()
        if isinstance(public_key, RSAPublicKey):
            return public_key.public_numbers()
        else:
            return None
    else:
        return None


def _send_robot_payload(
    server_info: ServerConnectivityInfo,
    tls_version_to_use: TlsVersionEnum,
    rsa_cipher_string: str,
    robot_payload_enum: RobotPmsPaddingPayloadEnum,
    robot_should_finish_handshake: bool,
    rsa_modulus: int,
    rsa_exponent: int,
) -> str:
    # Do a handshake which each record and keep track of what the server returned
    ssl_connection = server_info.get_preconfigured_tls_connection(override_tls_version=tls_version_to_use)

    # Replace nassl.sslClient.do_handshake() with a ROBOT checking SSL handshake so that all the SSLyze
    # options (startTLS, proxy, etc.) still work
    ssl_connection.ssl_client.do_handshake = types.MethodType(  # type: ignore
        do_handshake_with_robot, ssl_connection.ssl_client
    )
    ssl_connection.ssl_client.set_cipher_list(rsa_cipher_string)

    # Compute the  payload
    tls_parser_tls_version: tls_parser.tls_version.TlsVersionEnum
    if tls_version_to_use == TlsVersionEnum.SSL_3_0:
        tls_parser_tls_version = tls_parser.tls_version.TlsVersionEnum.SSLV3
    elif tls_version_to_use == TlsVersionEnum.TLS_1_0:
        tls_parser_tls_version = tls_parser.tls_version.TlsVersionEnum.TLSV1
    elif tls_version_to_use == TlsVersionEnum.TLS_1_1:
        tls_parser_tls_version = tls_parser.tls_version.TlsVersionEnum.TLSV1_1
    elif tls_version_to_use == TlsVersionEnum.TLS_1_2:
        tls_parser_tls_version = tls_parser.tls_version.TlsVersionEnum.TLSV1_2
    else:
        raise ValueError("Should never happen")

    cke_payload = _RobotTlsRecordPayloads.get_client_key_exchange_record(
        robot_payload_enum, tls_parser_tls_version, rsa_modulus, rsa_exponent
    )

    # H4ck: we need to pass some arguments to the handshake but there is no simple way to do it; we use an attribute
    ssl_connection.ssl_client._robot_cke_record = cke_payload  # type: ignore
    ssl_connection.ssl_client._robot_should_finish_handshake = robot_should_finish_handshake  # type: ignore

    server_response = ""
    try:
        # Start the SSL handshake
        ssl_connection.connect()
    except ServerResponseToRobot as e:
        # Should always be thrown
        server_response = e.server_response
    except socket.timeout:
        # https://github.com/nabla-c0d3/sslyze/issues/361
        server_response = "Connection timed out"
    except ServerRejectedTlsHandshake:
        if server_info.tls_probing_result.client_auth_requirement != ClientAuthRequirementEnum.DISABLED:
            # This error happens when scanning an nginx server with client authentication required;
            # If the server asks for a client cert, we cannot check for ROBOT as the check needs to complete full
            # handshakes. https://github.com/nabla-c0d3/sslyze/issues/484
            raise ClientCertificateRequested(ca_list=[])
        else:
            raise
    finally:
        ssl_connection.close()

    return server_response


class ServerResponseToRobot(Exception):
    def __init__(self, server_response: str) -> None:
        # Could be a TLS alert or some data, always as text so we can easily detect different responses
        self.server_response = server_response


def do_handshake_with_robot(self):  # type: ignore
    """Modified do_handshake() to send a ROBOT payload and return the result."""
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
    remaining_bytes = b""
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
            raise ValueError("Unknown record? Type {}".format(tls_record.header.type))

    if did_receive_hello_done:
        # Send a special Client Key Exchange Record as the payload
        self._sock.send(self._robot_cke_record.to_bytes())

        if self._robot_should_finish_handshake:
            # Then send a CCS record
            ccs_record = TlsChangeCipherSpecRecord.from_parameters(
                tls_version=tls_parser.tls_version.TlsVersionEnum[self._ssl_version.name]
            )
            self._sock.send(ccs_record.to_bytes())

            # Lastly send a Finished record
            finished_record_bytes = _RobotTlsRecordPayloads.get_finished_record_bytes(self._ssl_version)
            self._sock.send(finished_record_bytes)

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
                        raise ServerResponseToRobot("No data")
                except socket.error as e:
                    # Server closed the connection after receiving the CCS payload
                    raise ServerResponseToRobot("socket.error {}".format(str(e)))

                remaining_bytes = remaining_bytes + raw_ssl_bytes
                continue

            if isinstance(tls_record, TlsAlertRecord):
                raise ServerResponseToRobot(
                    "TLS Alert {} {}".format(tls_record.alert_description, tls_record.alert_severity)
                )
            else:
                break

        raise ServerResponseToRobot("Ok")
