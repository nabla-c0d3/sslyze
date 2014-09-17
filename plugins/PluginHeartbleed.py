#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginHeartbleed.py
# Purpose:      Tests the target server for CVE-2014-0160.
#
# Author:       alban
#
# Copyright:    2014 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import socket, new
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.SSLyzeSSLConnection import create_sslyze_connection, SSLHandshakeRejected
from nassl._nassl import OpenSSLError, WantX509LookupError, WantReadError
from nassl import TLSV1, TLSV1_1, TLSV1_2, SSLV23, SSLV3


class PluginHeartbleed(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface("PluginHeartbleed",  "")
    interface.add_command(
        command="heartbleed",
        help=(
            "Tests the server(s) for the OpenSSL Heartbleed vulnerability (experimental)."))


    def process_task(self, target, command, args):
        (host, ip, port, sslVersion) = target

        if sslVersion == SSLV23: # Could not determine the preferred  SSL version - client cert was required ?
            sslVersion = TLSV1 # Default to TLS 1.0
            target = (host, ip, port, sslVersion)

        sslConn = create_sslyze_connection(target, self._shared_settings)
        sslConn.sslVersion = sslVersion # Needed by the heartbleed payload

        # Awful hack #1: replace nassl.sslClient.do_handshake() with a heartbleed
        # checking SSL handshake so that all the SSLyze options
        # (startTLS, proxy, etc.) still work
        sslConn.do_handshake = new.instancemethod(do_handshake_with_heartbleed, sslConn, None)

        heartbleed = None
        try: # Perform the SSL handshake
            sslConn.connect()
        except HeartbleedSent:
            # Awful hack #2: directly read the underlying network socket
            heartbleed = sslConn._sock.recv(16381)
        finally:
            sslConn.close()

        # Text output
        if heartbleed is None:
            raise Exception("Error: connection failed.")
        elif '\x01\x01\x01\x01\x01\x01\x01\x01\x01' in heartbleed:
            # Server replied with our hearbeat payload
            heartbleedTxt = 'VULNERABLE - Server is vulnerable to Heartbleed'
            heartbleedXml = 'True'
        else:
            heartbleedTxt = 'OK - Not vulnerable to Heartbleed'
            heartbleedXml = 'False'

        cmdTitle = 'OpenSSL Heartbleed'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]
        txtOutput.append(self.FIELD_FORMAT(heartbleedTxt, ""))

        # XML output
        xmlOutput = Element(command, title=cmdTitle)
        if heartbleed:
            xmlNode = Element('heartbleed', isVulnerable=heartbleedXml)
            xmlOutput.append(xmlNode)

        return PluginBase.PluginResult(txtOutput, xmlOutput)




def heartbleed_payload(sslVersion):
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

    return payload.format(SSL_VERSION_MAPPING[sslVersion])


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
        lenToRead = self._networkBio.pending()
        while lenToRead:
            # Get the data from the SSL engine
            handshakeDataOut = self._networkBio.read(lenToRead)
            # Send it to the peer
            self._sock.send(handshakeDataOut)
            lenToRead = self._networkBio.pending()

        # Send the heartbleed payload after the client hello
        self._sock.send(heartbleed_payload(self.sslVersion))

        # Recover the peer's encrypted response
        # In this heartbleed handshake we only receive the server hello
        handshakeDataIn = self._sock.recv(2048)
        if len(handshakeDataIn) == 0:
            raise IOError('Nassl SSL handshake failed: peer did not send data back.')
        # Pass the data to the SSL engine
        self._networkBio.write(handshakeDataIn)

        # Signal that we sent the heartbleed payload and just stop the handshake
        raise HeartbleedSent("")


    except WantX509LookupError:
        # Server asked for a client certificate and we didn't provide one
        # Heartbleed should work anyway
        self._sock.send(heartbleed_payload(self.sslVersion)) # The heartbleed payload
        raise HeartbleedSent("") # Signal that we sent the heartbleed payload

