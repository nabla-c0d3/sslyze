# -*- coding: utf-8 -*-
"""Plugin to test the server for CVE-2014-0160.
"""



import new
from xml.etree.ElementTree import Element

from nassl import TLSV1, TLSV1_1, TLSV1_2, SSLV3
from nassl._nassl import WantX509LookupError, WantReadError

from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginResult
from sslyze.utils.ssl_connection import SSLHandshakeRejected


class HeartbleedPlugin(plugin_base.PluginBase):

    interface = plugin_base.PluginInterface("HeartbleedPlugin", "")
    interface.add_command(
        command="heartbleed",
        help="Tests the server(s) for the OpenSSL Heartbleed vulnerability (experimental)."
    )


    def process_task(self, server_info, command, options_dict=None):
        ssl_connection = server_info.get_preconfigured_ssl_connection()
        ssl_connection.ssl_version = server_info.highest_ssl_version_supported  # Needed by the heartbleed payload

        # Awful hack #1: replace nassl.sslClient.do_handshake() with a heartbleed
        # checking SSL handshake so that all the SSLyze options
        # (startTLS, proxy, etc.) still work
        ssl_connection.do_handshake = new.instancemethod(do_handshake_with_heartbleed, ssl_connection, None)

        heartbleed = None
        try: # Perform the SSL handshake
            ssl_connection.connect()
        except HeartbleedSent:
            # Awful hack #2: directly read the underlying network socket
            heartbleed = ssl_connection._sock.recv(16381)
        finally:
            ssl_connection.close()

        # Text output
        is_vulnerable_to_heartbleed = False
        if heartbleed is None:
            raise ValueError("Error: connection failed.")
        elif '\x01\x01\x01\x01\x01\x01\x01\x01\x01' in heartbleed:
            # Server replied with our hearbeat payload
            is_vulnerable_to_heartbleed = True

        return HeartbleedResult(server_info, command, options_dict, is_vulnerable_to_heartbleed)


class HeartbleedResult(PluginResult):
    """The result of running --heartbleed on a specific server.

    Attributes:
        is_vulnerable_to_heartbleed (bool): True if the server is vulnerable to the Heartbleed attack.
    """

    COMMAND_TITLE = 'OpenSSL Heartbleed'

    def __init__(self, server_info, plugin_command, plugin_options, is_vulnerable_to_heartbleed):
        super(HeartbleedResult, self).__init__(server_info, plugin_command, plugin_options)
        self.is_vulnerable_to_heartbleed = is_vulnerable_to_heartbleed

    def as_text(self):
        heartbleed_txt = 'VULNERABLE - Server is vulnerable to Heartbleed' \
            if self.is_vulnerable_to_heartbleed \
            else 'OK - Not vulnerable to Heartbleed'

        txt_output = [self.PLUGIN_TITLE_FORMAT(self.COMMAND_TITLE)]
        txt_output.append(self.FIELD_FORMAT("", heartbleed_txt))
        return txt_output

    def as_xml(self):
        xml_output = Element(self.plugin_command, title=self.COMMAND_TITLE)
        xml_output.append(Element('openSslHeartbleed', isVulnerable=str(self.is_vulnerable_to_heartbleed)))
        return xml_output



def heartbleed_payload(ssl_version):
    # This heartbleed payload does not exploit the server
    # https://blog.mozilla.org/security/2014/04/12/testing-for-heartbleed-vulnerability-without-exploiting-the-server/

    SSL_VERSION_MAPPING = {
        SSLV3 :  '\x00', # Surprising that it works with SSL 3 which doesn't define TLS extensions
        TLSV1 :  '\x01',
        TLSV1_1: '\x02',
        TLSV1_2: '\x03'}

    payload = (
        '\x18'           # Record type - Heartbeat
        '\x03{0}'               # TLS version
        '\x40\x00'              # Record length
        '\x01'                  # Heartbeat type - Request
        '\x3f\xfd')             # Heartbeat length

    payload += '\x01'*16381     # Heartbeat data

    payload += (                # Second Heartbeat request with no padding
        '\x18'                  # Record type - Heartbeat
        '\x03{0}'
        '\x00\x03\x01\x00\x00'
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
        if self._ssl.do_handshake() == 1:
            self._handshakeDone = True
            return True # Handshake was successful

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
            raise IOError('Nassl SSL handshake failed: peer did not send data back.')
        # Pass the data to the SSL engine
        self._network_bio.write(handshakeDataIn)

        # Signal that we sent the heartbleed payload and just stop the handshake
        raise HeartbleedSent("")


    except WantX509LookupError:
        # Server asked for a client certificate and we didn't provide one
        # Heartbleed should work anyway
        self._sock.send(heartbleed_payload(self.ssl_version)) # The heartbleed payload
        raise HeartbleedSent("") # Signal that we sent the heartbleed payload

