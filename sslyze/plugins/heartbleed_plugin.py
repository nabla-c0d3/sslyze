# -*- coding: utf-8 -*-

import types
from xml.etree.ElementTree import Element

from nassl._nassl import WantX509LookupError, WantReadError

from nassl.ssl_client import OpenSslVersionEnum
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SSLHandshakeRejected


class HeartbleedScanCommand(PluginScanCommand):
    """Test the server(s) for the OpenSSL Heartbleed vulnerability.
    """

    @classmethod
    def get_cli_argument(cls):
        return u'heartbleed'


class HeartbleedPlugin(plugin_base.Plugin):
    """Test the server(s) for the OpenSSL Heartbleed vulnerability (CVE-2014-0160).
    """

    @classmethod
    def get_available_commands(cls):
        return [HeartbleedScanCommand]

    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, HeartbleedScanCommand) -> HeartbleedScanResult
        ssl_connection = server_info.get_preconfigured_ssl_connection()
        ssl_connection.ssl_version = server_info.highest_ssl_version_supported  # Needed by the heartbleed payload

        # Awful hack #1: replace nassl.sslClient.do_handshake() with a heartbleed
        # checking SSL handshake so that all the SSLyze options
        # (startTLS, proxy, etc.) still work
        ssl_connection.do_handshake = types.MethodType(do_handshake_with_heartbleed, ssl_connection)

        heartbleed = None
        try:
            # Perform the SSL handshake
            ssl_connection.connect()
        except HeartbleedSent:
            # Awful hack #2: directly read the underlying network socket
            heartbleed = ssl_connection._sock.recv(16381)
        finally:
            ssl_connection.close()

        # Text output
        is_vulnerable_to_heartbleed = False
        if heartbleed is None:
            raise ValueError(u'Error: connection failed.')
        elif b'\x01\x01\x01\x01\x01\x01\x01\x01\x01' in heartbleed:
            # Server replied with our hearbeat payload
            is_vulnerable_to_heartbleed = True

        return HeartbleedScanResult(server_info, scan_command, is_vulnerable_to_heartbleed)


class HeartbleedScanResult(PluginScanResult):
    """The result of running a HeartbleedScanCommand on a specific server.

    Attributes:
        is_vulnerable_to_heartbleed (bool): True if the server is vulnerable to the Heartbleed attack.
    """

    COMMAND_TITLE = u'OpenSSL Heartbleed'

    def __init__(self, server_info, scan_command, is_vulnerable_to_heartbleed):
        # type: (ServerConnectivityInfo, HeartbleedScanCommand, bool) -> None
        super(HeartbleedScanResult, self).__init__(server_info, scan_command)
        self.is_vulnerable_to_heartbleed = is_vulnerable_to_heartbleed

    def as_text(self):
        heartbleed_txt = u'VULNERABLE - Server is vulnerable to Heartbleed' \
            if self.is_vulnerable_to_heartbleed \
            else u'OK - Not vulnerable to Heartbleed'

        return [self._format_title(self.COMMAND_TITLE), self._format_field(u"", heartbleed_txt)]

    def as_xml(self):
        xml_output = Element(self.scan_command.get_cli_argument(), title=self.COMMAND_TITLE)
        xml_output.append(Element('openSslHeartbleed', isVulnerable=str(self.is_vulnerable_to_heartbleed)))
        return xml_output


def heartbleed_payload(ssl_version):
    # This heartbleed payload does not exploit the server
    # https://blog.mozilla.org/security/2014/04/12/testing-for-heartbleed-vulnerability-without-exploiting-the-server/

    SSL_VERSION_MAPPING = {
        OpenSslVersionEnum.SSLV3: b'\x00',  # Surprising that it works with SSL 3 which doesn't define TLS extensions
        OpenSslVersionEnum.TLSV1: b'\x01',
        OpenSslVersionEnum.TLSV1_1: b'\x02',
        OpenSslVersionEnum.TLSV1_2: b'\x03'
    }

    payload = (
        b'\x18'             # Record type - Heartbeat
        b'\x03{0}'          # TLS version
        b'\x40\x00'         # Record length
        b'\x01'             # Heartbeat type - Request
        b'\x3f\xfd'         # Heartbeat length
    )

    payload += '\x01'*16381     # Heartbeat data

    payload += (                 # Second Heartbeat request with no padding
        b'\x18'                  # Record type - Heartbeat
        b'\x03{0}'
        b'\x00\x03\x01\x00\x00'
    )

    return payload.format(SSL_VERSION_MAPPING[ssl_version])


class HeartbleedSent(SSLHandshakeRejected):
    # Awful hack #3: Use an exception to hack the handshake's control flow in
    # a super obscure way
    pass


def do_handshake_with_heartbleed(self):
    # This is nassl's code for do_handshake() modified to send a heartbleed
    # payload that will send the heartbleed checking payload
    # I copied nassl's code here so I could leave anything heartbleed-related
    # outside of the nassl code base
    try:
        self._ssl.do_handshake()
        self._handshakeDone = True
        # Handshake was successful
        return

    except WantReadError:
        # OpenSSL is expecting more data from the peer
        # Send available handshake data to the peer
        # In this heartbleed handshake we only send the client hello
        lenToRead = self._network_bio.pending()
        while lenToRead:
            # Get the data from the SSL engine
            handshakeDataOut = self._network_bio.read(lenToRead)
            # Send it to the peer
            self._sock.send(handshakeDataOut)
            lenToRead = self._network_bio.pending()

        # Send the heartbleed payload after the client hello
        self._sock.send(heartbleed_payload(self.ssl_version))

        # Recover the peer's encrypted response
        # In this heartbleed handshake we only receive the server hello
        handshakeDataIn = self._sock.recv(2048)
        if len(handshakeDataIn) == 0:
            raise IOError(u'Nassl SSL handshake failed: peer did not send data back.')
        # Pass the data to the SSL engine
        self._network_bio.write(handshakeDataIn)

        # Signal that we sent the heartbleed payload and just stop the handshake
        raise HeartbleedSent("")


    except WantX509LookupError:
        # Server asked for a client certificate and we didn't provide one
        # Heartbleed should work anyway
        self._sock.send(heartbleed_payload(self.ssl_version))  # The heartbleed payload
        raise HeartbleedSent(u'')  # Signal that we sent the heartbleed payload

