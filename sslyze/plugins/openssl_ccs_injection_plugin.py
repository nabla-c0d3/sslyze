# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import socket
import struct
import random
from xml.etree.ElementTree import Element

from nassl.ssl_client import OpenSslVersionEnum
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SSLConnection


class OpenSslCcsInjectionScanCommand(plugin_base.PluginScanCommand):
    """Test the server(s) for the OpenSSL CCS injection vulnerability (CVE-2014-0224).
    """

    @classmethod
    def get_cli_argument(cls):
        return 'openssl_ccs'


class OpenSslCcsInjectionPlugin(plugin_base.Plugin):
    """Test the server(s) for the OpenSSL CCS injection vulnerability (CVE-2014-0224).
    """

    @classmethod
    def get_available_commands(cls):
        return [OpenSslCcsInjectionScanCommand]

    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, OpenSslCcsInjectionScanCommand) -> OpenSslCcsInjectionScanResult
        ssl_connection = server_info.get_preconfigured_ssl_connection()
        self._ssl_version = server_info.highest_ssl_version_supported
        is_vulnerable = False
        self._inbuffer = b''
        ssl_connection.do_pre_handshake(network_timeout=SSLConnection.NETWORK_TIMEOUT)

        # H4ck to directly send the CCS payload
        self._sock = ssl_connection._sock

        # Send hello and wait for server hello & cert
        serverhello, servercert = False, False
        self._sock.send(self.make_hello())
        while not serverhello:  # or not servercert
            try:
                if not self._srecv():
                    break
            except IOError:
                break
            rs = self.parse_records()
            for record in rs:
                if record['type'] == 22:
                    for p in record['proto']:
                        if p['type'] == 2:
                            serverhello = True
                        if p['type'] == 11:
                            servercert = True

        # Send the CCS
        if serverhello:  # and servercert:
            is_vulnerable, stop = True, False
            self._sock.send(self.make_ccs())
            while not stop:
                try:
                    if not self._srecv():
                        break
                except socket.timeout:
                    break
                except IOError:
                    is_vulnerable = False
                    stop = True

                rs = self.parse_records()
                for record in rs:
                    if record['type'] == 21:
                        for p in record['proto']:
                            if p['level'] == 2 or (p['level'] == 1 and p['desc'] == 0):
                                is_vulnerable = False
                                stop = True

            # If we receive no alert message check whether it is really is_vulnerable
            if is_vulnerable:
                self._sock.send(b'\x15' + self.ssl_tokens[self._ssl_version] + b'\x00\x02\x01\x00')

                try:
                    if not self._srecv():
                        is_vulnerable = False
                except IOError:
                    is_vulnerable = False

        self._sock.close()
        return OpenSslCcsInjectionScanResult(server_info, scan_command, is_vulnerable)

    def _srecv(self):
        r = self._sock.recv(4096)
        self._inbuffer += r
        return r != ''

    ssl_tokens = {
        OpenSslVersionEnum.SSLV3: b'\x03\x00',
        OpenSslVersionEnum.TLSV1: b'\x03\x01',
        OpenSslVersionEnum.TLSV1_1: b'\x03\x02',
        OpenSslVersionEnum.TLSV1_2: b'\x03\x03',
    }

    ssl3_cipher = [
        b'\x00\x00', b'\x00\x01', b'\x00\x02', b'\x00\x03',
        b'\x00\x04', b'\x00\x05', b'\x00\x06', b'\x00\x07',
        b'\x00\x08', b'\x00\x09', b'\x00\x0a', b'\x00\x0b',
        b'\x00\x0c', b'\x00\x0d', b'\x00\x0e', b'\x00\x0f',
        b'\x00\x10', b'\x00\x11', b'\x00\x12', b'\x00\x13',
        b'\x00\x14', b'\x00\x15', b'\x00\x16', b'\x00\x17',
        b'\x00\x18', b'\x00\x19', b'\x00\x1a', b'\x00\x1b',
        b'\x00\x1c', b'\x00\x1d', b'\x00\x1e',
        b'\x00\x1F', b'\x00\x20', b'\x00\x21', b'\x00\x22',
        b'\x00\x23', b'\x00\x24', b'\x00\x25', b'\x00\x26',
        b'\x00\x27', b'\x00\x28', b'\x00\x29', b'\x00\x2A',
        b'\x00\x2B', b'\x00\x2C', b'\x00\x2D', b'\x00\x2E',
        b'\x00\x2F', b'\x00\x30', b'\x00\x31', b'\x00\x32',
        b'\x00\x33', b'\x00\x34', b'\x00\x35', b'\x00\x36',
        b'\x00\x37', b'\x00\x38', b'\x00\x39', b'\x00\x3A',
        b'\x00\x3B', b'\x00\x3C', b'\x00\x3D', b'\x00\x3E',
        b'\x00\x3F', b'\x00\x40', b'\x00\x41', b'\x00\x42',
        b'\x00\x43', b'\x00\x44', b'\x00\x45', b'\x00\x46',
        b'\x00\x60', b'\x00\x61', b'\x00\x62', b'\x00\x63',
        b'\x00\x64', b'\x00\x65', b'\x00\x66', b'\x00\x67',
        b'\x00\x68', b'\x00\x69', b'\x00\x6A', b'\x00\x6B',
        b'\x00\x6C', b'\x00\x6D', b'\x00\x80', b'\x00\x81',
        b'\x00\x82', b'\x00\x83', b'\x00\x84', b'\x00\x85',
        b'\x00\x86', b'\x00\x87', b'\x00\x88', b'\x00\x89',
        b'\x00\x8A', b'\x00\x8B', b'\x00\x8C', b'\x00\x8D',
        b'\x00\x8E', b'\x00\x8F', b'\x00\x90', b'\x00\x91',
        b'\x00\x92', b'\x00\x93', b'\x00\x94', b'\x00\x95',
        b'\x00\x96', b'\x00\x97', b'\x00\x98', b'\x00\x99',
        b'\x00\x9A', b'\x00\x9B', b'\x00\x9C', b'\x00\x9D',
        b'\x00\x9E', b'\x00\x9F', b'\x00\xA0', b'\x00\xA1',
        b'\x00\xA2', b'\x00\xA3', b'\x00\xA4', b'\x00\xA5',
        b'\x00\xA6', b'\x00\xA7', b'\x00\xA8', b'\x00\xA9',
        b'\x00\xAA', b'\x00\xAB', b'\x00\xAC', b'\x00\xAD',
        b'\x00\xAE', b'\x00\xAF', b'\x00\xB0', b'\x00\xB1',
        b'\x00\xB2', b'\x00\xB3', b'\x00\xB4', b'\x00\xB5',
        b'\x00\xB6', b'\x00\xB7', b'\x00\xB8', b'\x00\xB9',
        b'\x00\xBA', b'\x00\xBB', b'\x00\xBC', b'\x00\xBD',
        b'\x00\xBE', b'\x00\xBF', b'\x00\xC0', b'\x00\xC1',
        b'\x00\xC2', b'\x00\xC3', b'\x00\xC4', b'\x00\xC5',
        b'\x00\x00', b'\xc0\x01', b'\xc0\x02', b'\xc0\x03',
        b'\xc0\x04', b'\xc0\x05', b'\xc0\x06', b'\xc0\x07',
        b'\xc0\x08', b'\xc0\x09', b'\xc0\x0a', b'\xc0\x0b',
        b'\xc0\x0c', b'\xc0\x0d', b'\xc0\x0e', b'\xc0\x0f',
        b'\xc0\x10', b'\xc0\x11', b'\xc0\x12', b'\xc0\x13',
        b'\xc0\x14', b'\xc0\x15', b'\xc0\x16', b'\xc0\x17',
        b'\xc0\x18', b'\xc0\x19', b'\xC0\x1A', b'\xC0\x1B',
        b'\xC0\x1C', b'\xC0\x1D', b'\xC0\x1E', b'\xC0\x1F',
        b'\xC0\x20', b'\xC0\x21', b'\xC0\x22', b'\xC0\x23',
        b'\xC0\x24', b'\xC0\x25', b'\xC0\x26', b'\xC0\x27',
        b'\xC0\x28', b'\xC0\x29', b'\xC0\x2A', b'\xC0\x2B',
        b'\xC0\x2C', b'\xC0\x2D', b'\xC0\x2E', b'\xC0\x2F',
        b'\xC0\x30', b'\xC0\x31', b'\xC0\x32', b'\xC0\x33',
        b'\xC0\x34', b'\xC0\x35', b'\xC0\x36', b'\xC0\x37',
        b'\xC0\x38', b'\xC0\x39', b'\xC0\x3A', b'\xC0\x3B',
        b'\xfe\xfe', b'\xfe\xff', b'\xff\xe0', b'\xff\xe1'
    ]


    # Create a TLS record out of a protocol packet
    def make_record(self, t, body):
        l = struct.pack("!H", len(body))
        return t + self.ssl_tokens[self._ssl_version] + l + body

    def make_hello(self):
        suites = b''.join(self.ssl3_cipher)
        rand = bytes(random.getrandbits(8) for _ in range(32))
        l = struct.pack("!L", 39+len(suites))[1:]  # 3 bytes
        sl = struct.pack("!H", len(suites))

        # Client hello, lenght and version
        # Random data + session ID + cipher suites + compression suites
        data = b'\x01' + l + self.ssl_tokens[self._ssl_version] + rand + b'\x00'
        data += sl + suites + b'\x01\x00'
        result = self.make_record(b'\x16', data)
        return result

    def make_ccs(self):
        ccsbody = b'\x01'  # Empty CCS
        result =  self.make_record(b'\x14', ccsbody)
        return result

    @staticmethod
    def parse_handshake_pkt(buf):
        r = []
        while len(buf) >= 4:
            mt = buf[0]
            mlen = struct.unpack("!L", buf[0:4])[0] & 0xFFFFFF

            if mlen+4 > len(buf):
                break

            r.append({"type": mt, "data": buf[4:4+mlen]})
            buf = buf[4+mlen:]
        return r

    @staticmethod
    def parse_alert_pkt(buf):
        return [{"level": buf[0], "desc": buf[1]}]

    def parse_records(self):
        r = []
        # 5 byte header
        while len(self._inbuffer) >= 5:
            mtype = self._inbuffer[0]
            mtlsv = self._inbuffer[1:3]
            mlen = struct.unpack("!H", self._inbuffer[3:5])[0]

            if len(self._inbuffer) < 5 + mlen:
                break

            if mtype == 22:  # Handshake
                protp = self.parse_handshake_pkt(self._inbuffer[5:5 + mlen])
            elif mtype == 21:  # Alert
                protp = self.parse_alert_pkt(self._inbuffer[5:5 + mlen])
            else:
                protp = []

            r.append({"type": mtype, "sslv": mtlsv, "proto": protp})

            self._inbuffer = self._inbuffer[5+mlen:]

        return r


class OpenSslCcsInjectionScanResult(PluginScanResult):
    """The result of running an OpenSslCcsInjectionScanCommand on a specific server.

    Attributes:
        is_vulnerable_to_ccs_injection (bool): True if the server is vulnerable to OpenSSL's CCS injection issue.
    """

    COMMAND_TITLE = 'OpenSSL CCS Injection'

    def __init__(self, server_info, scan_command, is_vulnerable_to_ccs_injection):
        # type: (ServerConnectivityInfo, OpenSslCcsInjectionScanCommand, bool) -> None
        super(OpenSslCcsInjectionScanResult, self).__init__(server_info, scan_command)
        self.is_vulnerable_to_ccs_injection = is_vulnerable_to_ccs_injection

    def as_xml(self):
        result_xml = Element(self.scan_command.get_cli_argument(), title=self.COMMAND_TITLE)
        result_xml.append(Element('openSslCcsInjection',
                                  attrib={'isVulnerable': str(self.is_vulnerable_to_ccs_injection)}))
        return result_xml

    def as_text(self):
        result_txt = [self._format_title(self.COMMAND_TITLE)]

        ccs_text = 'VULNERABLE - Server is vulnerable to OpenSSL CCS injection' \
            if self.is_vulnerable_to_ccs_injection \
            else 'OK - Not vulnerable to OpenSSL CCS injection'
        result_txt.append(self._format_field('', ccs_text))
        return result_txt
