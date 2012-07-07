#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginCertInfo.py
# Purpose:      Verifies the target server's certificate validity against
#               Mozilla's trusted root store, and prints relevant fields of the
#               certificate.
#
# Author:       aaron, alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
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

import os
import sys
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, constants, errors

TRUSTED_CA_STORE = os.path.join(sys.path[0], 'mozilla_cacert.pem')


# aaron:
# X.509 certificates contain several required and optional attributes that
# enable the identification of the subject. You can obtain the following list of
# attributes in an X.509 certificate:

    #Version number: The certificate version.
        #Note Different versions (version 1, 2, and 3) of X.509 certificates
        # have evolved over time, to provide additional security and attributes
        # that are bound to the certificate. In practice, only version 3
        # certificates should now be used.

    # Serial number: A unique identifier for the certificate.

    # Signature algorithm ID: The algorithm used to create the digital signature.

    # Issuer name: The name of the certificate issuer.

    # Validity period: The period during which the certificate is valid.

    # Subject name: The name of the subject represented by the certificate. (The
    # subject of a certificate is typically a person, an organization, or a
    # Web/application server.)

    # Subject public key information: The public key algorithm.

    # Issuer unique identifier: The identifier for the issuer.

    # Subject unique identifier: The identifier for the subject.

    # Extensions: Extensions that can be used to store additional information.
    # such as KeyUsage or AlternativeNames.

    # Signed hash of the certificate data: The hash of the preceding fields
    # encrypted using the issuer's private key, which results in a digital
    # signature.


class PluginCertInfo(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginCertInfo",
        description=(
            "Verifies the target server's certificate validity against "
            "Mozilla's trusted root store, and prints relevant fields of "
            "the certificate."))
    available_commands.add_command(
        command="certinfo",
        help="Should be one of: 'basic', 'full', 'serial', 'subject', 'keysize'.",
        dest="certinfo")

    FIELD_FORMAT = '      {0:<35}{1:<35}'
    
    def process_task(self, target, command, arg):

        ctSSL_initialize()
        cert_trusted = False

        try: # First verify the server's certificate
            cert = self._get_cert(target, verify_cert=True)
            cert_trusted = True

        except errors.SSLErrorSSL as e:
            # Recover the server's certificate without verifying it
            if 'certificate verify failed' in str(e.args):
                cert = self._get_cert(target, verify_cert=False)
            else:
                ctSSL_cleanup()
                raise
            
        result_dict = {'basic':     self._get_basic, 
                       'serial':    self._get_serial,
                       'keysize':   self._get_keysize,
                       'subject':   self._get_subject,
                       'full':      self._get_full}

        (cert_txt, cert_xml) = result_dict[arg](cert)
        
        # Text output
        cmd_title = 'Certificate'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        trust_txt = 'Certificate is Trusted' if cert_trusted \
                                             else 'Certificate is NOT Trusted'

        txt_result.append(self.FIELD_FORMAT.format("Validation w/ Mozilla's CA Store:", trust_txt))
        txt_result.extend(cert_txt)

        # XML output
        xml_result = Element(self.__class__.__name__, command = command, 
                             argument = arg, title = cmd_title)
        trust_xml_attr = {'trusted-by-mozilla' : str(cert_trusted)}
        trust_xml = Element('certificate', attrib = trust_xml_attr)
        for elem_xml in cert_xml:
            trust_xml.append(elem_xml)
        xml_result.append(trust_xml)
        
        ctSSL_cleanup()
        return PluginBase.PluginResult(txt_result, xml_result)


# FORMATTING FUNCTIONS
    def _get_basic(self, cert):
        basic_xml = []
        basic_txt = []
        
        vals_to_get = [self._get_subject(cert), self._get_issuer(cert),
                       self._get_serial(cert),self._get_not_before(cert),
                       self._get_not_after(cert), self._get_sig_algorithm(cert),
                       self._get_keysize(cert), self._get_fingerprint(cert)]
        
        for (val_txt, val_xml) in vals_to_get:
            basic_xml.extend(val_xml)
            basic_txt.extend(val_txt)

        return (basic_txt, basic_xml)

    def _get_serial(self, cert):
        sn = cert.get_serial_number()
        serial_txt = self.FIELD_FORMAT.format('Serial Number:', sn)
        serial_xml = Element('serial')
        serial_xml.text = sn
        return ([serial_txt], [serial_xml])

    def _get_keysize(self, cert):
        keysize = cert.get_pubkey_size()*8
        keysize_txt = self.FIELD_FORMAT.format('Key Size:', str(keysize) + ' bits')
        keysize_xml = Element('pk', keysize=str(keysize))
        return ([keysize_txt],[keysize_xml])   

    def _get_not_before(self, cert):
        nb = cert.get_not_before()
        val_txt = self.FIELD_FORMAT.format('Not Before:', nb)
        val_xml = Element('not-before')
        val_xml.text = nb
        return ([val_txt], [val_xml])

    def _get_not_after(self, cert):
        nb = cert.get_not_after()
        val_txt = self.FIELD_FORMAT.format('Not After:', nb)
        val_xml = Element('not-after')
        val_xml.text = nb
        return ([val_txt], [val_xml])

    def _get_issuer(self, cert):
        nb = cert.get_issuer()
        val_txt = self.FIELD_FORMAT.format('Issuer:', nb)
        val_xml = Element('issuer')
        val_xml.text = nb
        return ([val_txt], [val_xml])    
      
    def _get_sig_algorithm(self, cert):
        nb = cert.get_sig_algorithm()
        val_txt = self.FIELD_FORMAT.format('Signature Algorithm:', nb)
        val_xml = Element('signature-algorithm')
        val_xml.text = nb
        return ([val_txt], [val_xml])    

    def _get_fingerprint(self, cert):
        nb = cert.get_fingerprint()
        val_txt = self.FIELD_FORMAT.format('SHA1 Fingerprint:', nb)
        val_xml = Element('fingerprint', algorithm='sha1')
        val_xml.text = nb
        return ([val_txt], [val_xml])    

    def _get_subject(self, cert):
        nb = cert.get_subject()
        val_txt = self.FIELD_FORMAT.format('Subject:', nb)
        val_xml = Element('subject')
        val_xml.text = nb
        return ([val_txt], [val_xml]) 

    def _get_full(self, cert):
        # TODO: Proper parsing of the cert for XML output
        full_cert = cert.as_text()
        # Removing the first and the last lines
        full_cert = full_cert.rsplit('\n', 1)[0]
        full_cert_txt = full_cert.split('\n', 1)[1]
        full_cert_xml = Element('raw-certificate')
        full_cert_xml.text = full_cert_txt
        return ([full_cert_txt], [full_cert_xml])
        

    def _get_cert(self, target, verify_cert=False):
        """
        Connects to the target server and returns the server's certificate if
        the connection was successful.
        """
        ssl_connect = self._create_ssl_connection(target)
        ssl_connect.ssl_ctx.set_cipher_list(self.hello_workaround_cipher_list)
        if verify_cert:
            ssl_connect.ssl_ctx.load_verify_locations(TRUSTED_CA_STORE)
            ssl_connect.ssl.set_verify(constants.SSL_VERIFY_PEER)

        try: # Perform the SSL handshake
            ssl_connect.connect()
            cert = ssl_connect.ssl.get_peer_certificate()
        finally:
            ssl_connect.close()

        return cert
