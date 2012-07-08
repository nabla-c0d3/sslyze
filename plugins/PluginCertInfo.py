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


class PluginCertInfo(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginCertInfo",
        description=(
            "Verifies the target server's certificate validity against "
            "Mozilla's trusted root store, and prints relevant fields of "
            "the certificate."))
    available_commands.add_command(
        command="certinfo",
        help="Should be one of: 'basic', 'detail' or 'full'",
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
                       'detail':     self._get_detail, 
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

# TODO: Write results to an object and use an XML serializer instead

    def _get_basic(self, cert):
        basic_xml = []
        basic_txt = []
        
        vals_to_get = [self._get_subject(cert), self._get_issuer(cert),
                       self._get_serial(cert),self._get_validity(cert),
                       self._get_sig_algorithm(cert),
                       self._get_keysize(cert), self._get_fingerprint(cert),
                       self._get_subject_alternative_name(cert)]
        
        for (val_txt, val_xml) in vals_to_get:
            basic_xml.extend(val_xml)
            basic_txt.extend(val_txt)

        return (basic_txt, basic_xml)
    
    
    def _get_detail(self, cert):
        basic_xml = []
        basic_txt = []
        
        vals_to_get = [self._get_subject(cert), self._get_issuer(cert),
                       self._get_serial(cert),self._get_validity(cert),
                       self._get_sig_algorithm(cert),
                       self._get_keysize(cert), self._get_fingerprint(cert),
                       self._get_all_extensions(cert)]
        
        for (val_txt, val_xml) in vals_to_get:
            basic_xml.extend(val_xml)
            basic_txt.extend(val_txt)

        return (basic_txt, basic_xml)
    
    
    def _subject_alternative_name_to_xml(self, alt_name):
        alt_name_xml = []
        
        # Parse the names for a useful xml output TODO: do it somewhere else
        alt_name = alt_name.replace(' ', '')
        alt_name_l = alt_name.split(',')
        for name in alt_name_l:
            name_val = name.split(':')
            name_xml = Element(name_val[0])
            name_xml.text = name_val[1]
            alt_name_xml.append(name_xml)
        
        return alt_name_xml
        
    def _authority_information_access_to_xml(self, auth_ext):
        # Hazardous attempt at parsing an Authority Information Access extension
        auth_ext = auth_ext.strip(' \n')
        auth_ext = auth_ext.split('\n')
        auth_xml = []
        for auth_entry in auth_ext:
            auth_entry = auth_entry.split(' - ')
            auth_entry_xml = Element(auth_entry[0].replace(' ', ''))
            auth_entry_data = auth_entry[1].split(':', 1)
            auth_entry_data_xml = Element(auth_entry_data[0])
            auth_entry_data_xml.text = auth_entry_data[1]
            auth_entry_xml.append(auth_entry_data_xml)
            auth_xml.append(auth_entry_xml)
            
        return auth_xml
            
              
    def _crl_distribution_points_to_xml(self, crl_ext):
        # Hazardous attempt at parsing a CRL Distribution Point extension
        crl_ext = crl_ext.strip(' \n')
        crl_ext = crl_ext.split('\n')
        subcrl_xml = []
        
        for distrib_point in crl_ext:
            distrib_point = distrib_point.strip()
            distrib_point = distrib_point.split(':', 1)
            distrib_point_xml = Element(distrib_point[0].replace(' ', ''))
            distrib_point_xml.text = distrib_point[1]
            subcrl_xml.append(distrib_point_xml)
            
        return subcrl_xml
        
    def _extended_key_usage_to_xml(self, key_ext):
        key_ext = key_ext.split(', ')
        key_ext_xml = []
        for key_usage in key_ext:
            key_usage_xml = Element(key_usage.replace(' ', ''))
            key_ext_xml.append(key_usage_xml)
        return key_ext_xml
            
                
    def _get_all_extensions(self, cert):
        ext_dict = cert.get_extension_list().get_all_extensions()
        ext_list_txt = ['', self.FIELD_FORMAT.format('Extensions', '')]
        ext_list_xml = Element('extensions')
        
        xml_format_functions = {'X509v3 Subject Alternative Name': self._subject_alternative_name_to_xml,
                                'X509v3 CRL Distribution Points': self._crl_distribution_points_to_xml,
                                'Authority Information Access': self._authority_information_access_to_xml,
                                'X509v3 Key Usage': self._extended_key_usage_to_xml,
                                'X509v3 Extended Key Usage': self._extended_key_usage_to_xml}
        
        for ext in ext_dict.items():
            ext_list_txt.append(self.FIELD_FORMAT.format(ext[0], ext[1]))
            ext_name = ext[0].replace(' ', '').replace('/','')
            if ext_name[0].isdigit(): # Unknown extension, would generate invalid XML
                ext_name = 'ext-' + ext_name # Tags cannot start with a digit
            ext_xml = Element(ext_name)
            
            if ext[0] in xml_format_functions.keys(): # Special XML formatting
                for xml_node in xml_format_functions[ext[0]](ext[1]):
                    ext_xml.append(xml_node)
            else:
                ext_xml.text = ext[1]
            ext_list_xml.append(ext_xml)
        
        return (ext_list_txt, [ext_list_xml])
        
        
    def _get_subject_alternative_name(self, cert):
        try:
            alt_name = cert.get_extension_list().get_extension('X509v3 Subject Alternative Name')
        except KeyError: 
            return ([],[])
        
        alt_name_txt = self.FIELD_FORMAT.format('X509v3 Subject Alternative Name:', alt_name)
        
        val_xml = Element('extensions')
        alt_name_xml = self._subject_alternative_name_to_xml(alt_name)
        val_xml.append(alt_name_xml)
        return ([alt_name_txt],[val_xml])
        

    def _get_serial(self, cert):
        sn = cert.get_serial_number()
        serial_txt = self.FIELD_FORMAT.format('Serial Number:', sn)
        serial_xml = Element('serialNumber')
        serial_xml.text = sn
        return ([serial_txt], [serial_xml])

    def _get_keysize(self, cert):
        keysize = cert.get_pubkey_size()*8
        keysize_txt = self.FIELD_FORMAT.format('Key Size:', str(keysize) + ' bits')
        keysize_xml = Element('publicKey', keysize=str(keysize))
        return ([keysize_txt],[keysize_xml])   

    def _get_validity(self, cert):
        val_xml = Element('validity')
        #val_txt = []
        # Not before
        nb = cert.get_not_before()
        val_txt = self.FIELD_FORMAT.format('Not Before:', nb)
        subval_xml = Element('notBefore')
        subval_xml.text = nb
        val_xml.append(subval_xml)
        
        # Not After
        nb = cert.get_not_after()
        val2_txt = self.FIELD_FORMAT.format('Not After:', nb)
        subval2_xml = Element('notAfter')
        subval2_xml.text = nb
        val_xml.append(subval2_xml)
        return ([val_txt, val2_txt], [val_xml])        

    def _get_issuer(self, cert):
        issuer_name = cert.get_issuer_name()
        val_txt = self.FIELD_FORMAT.format('Issuer:', issuer_name.get_as_text())
        val_xml = Element('issuer')
        for (field_name, field_value) in issuer_name.get_all_entries().items():
            if field_name[0].isdigit(): # Would generate invalid XML
                field_name = 'field-' + field_name # Tags cannot start with a digit
            
            subval_xml = Element(field_name)
            subval_xml.text = field_value
            val_xml.append(subval_xml)
        return ([val_txt], [val_xml])    
      
    def _get_sig_algorithm(self, cert):
        nb = cert.get_sig_algorithm()
        val_txt = self.FIELD_FORMAT.format('Signature Algorithm:', nb)
        val_xml = Element('signatureAlgorithm')
        val_xml.text = nb
        return ([val_txt], [val_xml])    

    def _get_fingerprint(self, cert):
        nb = cert.get_fingerprint()
        val_txt = self.FIELD_FORMAT.format('SHA1 Fingerprint:', nb)
        val_xml = Element('fingerprint', algorithm='sha1')
        val_xml.text = nb
        return ([val_txt], [val_xml])    

    def _get_subject(self, cert):
        subject_name = cert.get_subject_name()
        cn = subject_name.get_entry('commonName')
        val_txt = self.FIELD_FORMAT.format('Common Name:', cn)
        val_xml = Element('subject')
        for (field_name, field_value) in subject_name.get_all_entries().items():
            if field_name[0].isdigit(): # Would generate invalid XML
                field_name = 'field-' + field_name # Tags cannot start with a digit
            subval_xml = Element(field_name)
            subval_xml.text = field_value
            val_xml.append(subval_xml)
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
