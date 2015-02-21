#!/usr/bin/env python
# -*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:         PluginSNI.py
# Purpose:      Checks if the server is using SNI
#
# Author:       Oscar Koeroo
#
# Copyright:    2015 SSLyze developers
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

from xml.etree.ElementTree import Element
from utils.HTTPResponseParser import parse_http_response
from utils.SSLyzeSSLConnection import create_sslyze_connection
from plugins import PluginBase
from urlparse import urlparse
import Cookie


class PluginSNI(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginSNI", description=(''))
    interface.add_command(
        command="snitest",
        help="Checks support for Server Name Indication by trying "
             "to connect with an without SNI enabled. Server Name "
             "Indication (SNI) is an extension to TLS.",
        dest=None)


    def process_task(self, target, command, args):
        sni_supported = self._get_sni_support(target)
        if sni_supported:
            sni_timeout = sni_supported
            sni_supported = True

        # Text output
        cmd_title = 'SNI tester'
        txt_result = [self.PLUGIN_TITLE_FORMAT(cmd_title)]
        if sni_supported:
            txt_result.append(self.FIELD_FORMAT("YES - SNI is in use.", ""))
        else:
            txt_result.append(self.FIELD_FORMAT("NO - SNI was not detected/activated. Could be a false-negative if the target host provides the same certificate for the default SSL Virtual Host.", ""))

        # XML output
        xml_sni_attr = {'has_SniSupport': str(sni_supported)}
        if sni_supported:
            xml_sni_attr['sniHeaderValue'] = sni_timeout
        xml_sni = Element('snitest', attrib = xml_sni_attr)

        xml_result = Element('snitest', title = cmd_title)
        xml_result.append(xml_sni)

        return PluginBase.PluginResult(txt_result, xml_result)



    def _get_sni_support(self, target):
        (host, _, _, _) = target

        # Save
        stored_val = self._shared_settings['sni']

        # With normal SNI
        self._shared_settings['sni'] = host
        sslConn = create_sslyze_connection(target, self._shared_settings)

        # Perform the SSL handshake
        sslConn.connect()
        x509Chain1 = sslConn.get_peer_cert_chain()
        x509Cert1 = x509Chain1[0] # First cert is always the leaf cert
        sslConn.close()

        # Debug
        # for (key, value) in x509Cert1.as_dict().items():
        #    print key, value


        # With faked SNI - expecting a different value
        #                  Forcing a fake SNI will serve equal to serving none.
        #                  Serving None is not an option due to default served
        #                  SNI value from the create_sslyze_connection when none
        #                  is provided.
        self._shared_settings['sni'] = 'fake_SNI'
        sslConn = create_sslyze_connection(target, self._shared_settings)

        # Perform the SSL handshake
        sslConn.connect()
        x509Chain2 = sslConn.get_peer_cert_chain()
        x509Cert2 = x509Chain2[0] # First cert is always the leaf cert
        sslConn.close()

        # Debug
        # for (key, value) in x509Cert2.as_dict().items():
        #    print key, value


        # Restore
        self._shared_settings['sni'] = stored_val

        # Match fingerprints
        if x509Cert1.get_SHA1_fingerprint() == x509Cert2.get_SHA1_fingerprint():
           return False
        else:
           return True

