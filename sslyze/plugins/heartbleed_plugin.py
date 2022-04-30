import socket
import types
from dataclasses import dataclass
from typing import List, Optional

import pydantic
from nassl._nassl import WantReadError

from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanJob,
    ScanCommandExtraArgument,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
    ScanJobResult,
)
from tls_parser.alert_protocol import TlsAlertRecord
from tls_parser.exceptions import NotEnoughData, UnknownTlsVersionByte
from tls_parser.handshake_protocol import TlsHandshakeRecord, TlsHandshakeTypeByte
from tls_parser.heartbeat_protocol import TlsHeartbeatRequestRecord
from tls_parser.parser import TlsRecordParser
import tls_parser.record_protocol

from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum


@dataclass(frozen=True)
class HeartbleedScanResult(ScanCommandResult):
    """The result of testing a server for the OpenSSL Heartbleed vulnerability.

    Attributes:
        is_vulnerable_to_heartbleed: True if the server is vulnerable to the Heartbleed attack.
    """

    is_vulnerable_to_heartbleed: bool


# Identical fields in the JSON output
HeartbleedScanResultAsJson = pydantic.dataclasses.dataclass(HeartbleedScanResult, frozen=True)


class HeartbleedScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[HeartbleedScanResultAsJson]  # type: ignore


class _HeartbleedCliConnector(ScanCommandCliConnector[HeartbleedScanResult, None]):

    _cli_option = "heartbleed"
    _cli_description = "Test a server for the OpenSSL Heartbleed vulnerability."

    @classmethod
    def result_to_console_output(cls, result: HeartbleedScanResult) -> List[str]:
        result_as_txt = [cls._format_title("OpenSSL Heartbleed")]
        heartbleed_txt = (
            "VULNERABLE - Server is vulnerable to Heartbleed"
            if result.is_vulnerable_to_heartbleed
            else "OK - Not vulnerable to Heartbleed"
        )
        result_as_txt.append(cls._format_field("", heartbleed_txt))
        return result_as_txt


class HeartbleedImplementation(ScanCommandImplementation[HeartbleedScanResult, None]):
    """Test a server for the OpenSSL Heartbleed vulnerability."""

    cli_connector_cls = _HeartbleedCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        return [ScanJob(function_to_call=_test_heartbleed, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> HeartbleedScanResult:
        if len(scan_job_results) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        return HeartbleedScanResult(is_vulnerable_to_heartbleed=scan_job_results[0].get_result())


def _test_heartbleed(server_info: ServerConnectivityInfo) -> bool:
    if server_info.tls_probing_result.highest_tls_version_supported.value >= TlsVersionEnum.TLS_1_3.value:
        # The server uses a recent version of OpenSSL and it cannot be vulnerable to Heartbleed
        return False

    # Disable SNI for this check because some legacy servers don't support sending the heartbleed payload and SNI
    # See https://github.com/nabla-c0d3/sslyze/issues/202
    ssl_connection = server_info.get_preconfigured_tls_connection(should_enable_server_name_indication=False)

    # Replace nassl.sslClient.do_handshake() with a heartbleed checking SSL handshake so that all the SSLyze options
    # (startTLS, proxy, etc.) still work
    ssl_connection.ssl_client.do_handshake = types.MethodType(  # type: ignore
        _do_handshake_with_heartbleed, ssl_connection.ssl_client
    )

    is_vulnerable_to_heartbleed = False
    try:
        # Start the SSL handshake
        ssl_connection.connect()
    except _VulnerableToHeartbleed:
        # The test was completed and the server is vulnerable
        is_vulnerable_to_heartbleed = True
    except _NotVulnerableToHeartbleed:
        # The test was completed and the server is NOT vulnerable
        pass
    finally:
        ssl_connection.close()

    return is_vulnerable_to_heartbleed


class _VulnerableToHeartbleed(Exception):
    """Exception to raise during the handshake to hijack the flow and test for Heartbleed."""


class _NotVulnerableToHeartbleed(Exception):
    """Exception to raise during the handshake to hijack the flow and test for Heartbleed."""


def _do_handshake_with_heartbleed(self):  # type: ignore
    """Modified do_handshake() to send a heartbleed payload and return the result."""
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

    # Build the heartbleed payload - based on
    # https://blog.mozilla.org/security/2014/04/12/testing-for-heartbleed-vulnerability-without-exploiting-the-server/
    payload = TlsHeartbeatRequestRecord.from_parameters(
        tls_version=tls_parser.record_protocol.TlsVersionEnum[self._ssl_version.name], heartbeat_data=b"\x01" * 16381
    ).to_bytes()

    payload += TlsHeartbeatRequestRecord.from_parameters(
        tls_parser.record_protocol.TlsVersionEnum[self._ssl_version.name], heartbeat_data=b"\x01\x00\x00"
    ).to_bytes()

    # Send the payload
    self._sock.send(payload)

    # Retrieve the server's response - directly read the underlying network socket
    # Retrieve data until we get to the ServerHelloDone
    # The server may send back a ServerHello, an Alert, a CertificateRequest or may just close the connection
    did_receive_hello_done = False
    remaining_bytes = b""
    while not did_receive_hello_done:
        try:
            tls_record, len_consumed = TlsRecordParser.parse_bytes(remaining_bytes)
            remaining_bytes = remaining_bytes[len_consumed::]
        except UnknownTlsVersionByte as e:
            # Workaround for Amazon Cloudfront; see https://github.com/nabla-c0d3/sslyze/issues/437
            if e.record_type == tls_parser.record_protocol.TlsRecordTypeByte.ALERT:
                # Server returned a (badly-formatted) TLS alert because it requires SNI
                # Hence the server uses a modern TLS stack and is not vulnerable
                raise _NotVulnerableToHeartbleed()
            else:
                raise
        except NotEnoughData:
            # Try to get more data
            try:
                raw_ssl_bytes = self._sock.recv(16381)
            except socket.error:
                # Server closed the connection as soon as it received the Heartbleed payload
                raise _NotVulnerableToHeartbleed()

            if not raw_ssl_bytes:
                # No data?
                raise _NotVulnerableToHeartbleed()

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

    is_vulnerable_to_heartbleed = False
    if did_receive_hello_done:
        expected_heartbleed_payload = b"\x01" * 10
        if expected_heartbleed_payload in remaining_bytes:
            # Server replied with our heartbeat payload
            is_vulnerable_to_heartbleed = True
        else:
            try:
                raw_ssl_bytes = self._sock.recv(16381)
            except socket.error:
                # Server closed the connection after receiving the heartbleed payload
                raise _NotVulnerableToHeartbleed()

            if expected_heartbleed_payload in raw_ssl_bytes:
                # Server replied with our heartbeat payload
                is_vulnerable_to_heartbleed = True

    if is_vulnerable_to_heartbleed:
        raise _VulnerableToHeartbleed()
    else:
        raise _NotVulnerableToHeartbleed()
