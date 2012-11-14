#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginCertInfo.py
# Purpose:      Verifies the target server's certificate validity against
#               Mozilla's trusted root store, and prints relevant fields of the
#               certificate.
#
# Author:       aaron, alban
#
# Copyright:    2012 SSLyze developers
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
import re
import imp
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, constants, \
    X509_V_CODES, SSL_CTX
from utils.SSLyzeSSLConnection import SSLyzeSSLConnection


# Import Mozilla trust store and EV OIDs
DATA_PATH = os.path.join(os.path.dirname(PluginBase.__file__) , 'data')
MOZILLA_CA_STORE = os.path.join(DATA_PATH, 'mozilla_cacert.pem')
MOZILLA_EV_OIDS = imp.load_source('mozilla_ev_oids',
                                  os.path.join(DATA_PATH,  'mozilla_ev_oids.py')).MOZILLA_EV_OIDS


class X509CertificateHelper:
    # TODO: Move this somewhere else
    """
    Helper functions for X509 certificate parsing and XML serialization.
    """
    
    def __init__(self, certificate):
        self._cert = certificate
        
    def parse_certificate(self):
        cert_dict = \
            {'version': self._cert.get_version().split('(')[0].strip() ,
             'serialNumber': self._cert.get_serial_number() ,
             'issuer': self._cert.get_issuer_name().get_all_entries() ,
             'validity': {'notBefore': self._cert.get_not_before() ,
                         'notAfter' : self._cert.get_not_after()} ,
             'subject': self._cert.get_subject_name().get_all_entries() ,
             'subjectPublicKeyInfo':{'publicKeyAlgorithm': self._cert.get_pubkey_algorithm() ,
                                     'publicKeySize': str( self._cert.get_pubkey_size()*8) ,
                                     'publicKey': {'modulus': self._cert.get_pubkey_modulus_as_text(),
                                                   'exponent': self._cert.get_pubkey_exponent_as_text()}
                                     },
             'extensions': self._get_all_extensions() ,
             'signatureAlgorithm': self._cert.get_signature_algorithm() ,
             'signatureValue': self._cert.get_signature_as_text() }
        
        return cert_dict
        

    def parse_certificate_to_xml(self):
        cert_dict = self.parse_certificate()
        cert_xml = []
        
        for (key, value) in cert_dict.items():
            for xml_elem in self._keyvalue_pair_to_xml(key, value):
                cert_xml.append(xml_elem)
 
        return cert_xml


    def _create_xml_node(self, key, value=''):
        key = key.replace(' ', '').strip() # Remove spaces
        key = key.replace('/', '').strip() # Remove slashes (S/MIME Capabilities)
        
         # Things that would generate invalid XML
        if key[0].isdigit(): # Tags cannot start with a digit
                key = 'oid-' + key 
                
        xml_node = Element(key)
        xml_node.text = value.decode( "utf-8" ).strip()
        return xml_node
    
    
    def _keyvalue_pair_to_xml(self, key, value=''):
        res_xml = []
        
        if type(value) is str: # value is a string
            key_xml = self._create_xml_node(key)
            key_xml.text = value
            res_xml.append(key_xml)
            
        elif value is None: # no value
           res_xml.append(self._create_xml_node(key))
           
        elif type(value) is list: # multiple strings
            for val in value:
                res_xml.append(self._create_xml_node(key, val))
           
        elif type(value) is dict: # value is a list of subnodes
            key_xml = self._create_xml_node(key)
            for subkey in value.keys():
                for subxml in self._keyvalue_pair_to_xml(subkey, value[subkey]):
                    key_xml.append(subxml)
                 
            res_xml.append(key_xml)
            
        return res_xml    


    def _parse_multi_valued_extension(self, extension):
        
        extension = extension.split(', ')
        # Split the (key,value) pairs
        parsed_ext = {}
        for value in extension:
            value = value.split(':', 1)
            if len(value) == 1:
                parsed_ext[value[0]] = ''
            else:
                if parsed_ext.has_key(value[0]):
                    parsed_ext[value[0]].append(value[1])
                else:
                    parsed_ext[value[0]] = [value[1]]

        return parsed_ext
        
    
    def _parse_authority_information_access(self, auth_ext):
        # Hazardous attempt at parsing an Authority Information Access extension
        auth_ext = auth_ext.strip(' \n').split('\n')
        auth_ext_list = {}
         
        for auth_entry in auth_ext:
            auth_entry_res = []
            auth_entry = auth_entry.split(' - ')
            entry_name = auth_entry[0].replace(' ', '')

            if not auth_ext_list.has_key(entry_name):
                auth_ext_list[entry_name] = {}
            
            entry_data = auth_entry[1].split(':', 1)
            if auth_ext_list[entry_name].has_key(entry_data[0]):
                auth_ext_list[entry_name][entry_data[0]].append(entry_data[1])
            else:
                auth_ext_list[entry_name] = {entry_data[0]: [entry_data[1]]}
                
        return auth_ext_list
            
              
    def _parse_crl_distribution_points(self, crl_ext):
        # Hazardous attempt at parsing a CRL Distribution Point extension
        crl_ext = crl_ext.strip(' \n').split('\n')
        subcrl = {}

        for distrib_point in crl_ext:
            distrib_point = distrib_point.strip()
            distrib_point = distrib_point.split(':', 1)
            if distrib_point[0] != '':
                if subcrl.has_key(distrib_point[0].strip()):
                    subcrl[distrib_point[0].strip()].append(distrib_point[1].strip())
                else:
                    subcrl[distrib_point[0].strip()] = [(distrib_point[1].strip())]

        return subcrl
        
                
    def _get_all_extensions(self):

        ext_dict = self._cert.get_extension_list().get_all_extensions()

        parsing_functions = {'X509v3 Subject Alternative Name': self._parse_multi_valued_extension,
                             'X509v3 CRL Distribution Points': self._parse_crl_distribution_points,
                             'Authority Information Access': self._parse_authority_information_access,
                             'X509v3 Key Usage': self._parse_multi_valued_extension,
                             'X509v3 Extended Key Usage': self._parse_multi_valued_extension,
                             'X509v3 Certificate Policies' : self._parse_crl_distribution_points,
                             'X509v3 Issuer Alternative Name' : self._parse_crl_distribution_points}
        
        for (ext_key, ext_val) in ext_dict.items():
            # Overwrite the data we have if we know how to parse it
            if ext_key in parsing_functions.keys():
                ext_dict[ext_key] = parsing_functions[ext_key](ext_val)

        return ext_dict
        

class PluginCertInfo(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCertInfo", description=(''))
    interface.add_command(
        command="certinfo",
        help= "Verifies the target server's certificate validity against "
            "Mozilla's trusted root store, and prints relevant fields of "
            "the certificate. CERTINFO should be 'basic' or 'full'.",
        dest="certinfo")

    FIELD_FORMAT = '      {0:<35}{1:<35}'
    
    def process_task(self, target, command, arg):

        ctSSL_initialize()
        try: # Get the certificate
             (cert, verify_result) = self._get_cert(target)
        except:
            ctSSL_cleanup()
            raise
        
        # Figure out if/why the verification failed
        untrusted_reason = None
        is_cert_trusted = True
        if verify_result != 0:
            is_cert_trusted = False
            untrusted_reason = X509_V_CODES.X509_V_CODES[verify_result]
         
        # Results formatting
        cert_parsed = X509CertificateHelper(cert)
        cert_dict = cert_parsed.parse_certificate()
        
        # Text output
        if arg == 'basic':
            cert_txt = self._get_basic_text(cert, cert_dict)
        elif arg == 'full':
            cert_txt = [cert.as_text()]
        else:
            raise Exception("PluginCertInfo: Unknown command.")
            
        fingerprint = cert.get_fingerprint()
        cmd_title = 'Certificate'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        trust_txt = 'Certificate is Trusted' if is_cert_trusted \
                                             else 'Certificate is NOT Trusted'

        is_ev = self._is_ev_certificate(cert_dict)
        if is_ev:
            trust_txt = trust_txt + ' - Extended Validation'
            
        if untrusted_reason:
            trust_txt = trust_txt + ': ' + untrusted_reason

        txt_result.append(self.FIELD_FORMAT.format("Validation w/ Mozilla's CA Store:", trust_txt))
        
        is_host_valid = self._is_hostname_valid(cert_dict, target)
        host_txt = 'OK - ' + is_host_valid + ' Matches' if is_host_valid \
                                         else 'MISMATCH'
        
        txt_result.append(self.FIELD_FORMAT.format("Hostname Validation:", host_txt))
        txt_result.append(self.FIELD_FORMAT.format('SHA1 Fingerprint:', fingerprint))
        txt_result.append('')
        txt_result.extend(cert_txt)

        # XML output: always return the full certificate
        host_xml = True if is_host_valid \
                        else False
            
        xml_result = Element(command, argument = arg, title = cmd_title)
        trust_xml_attr = {'isTrustedByMozillaCAStore' : str(is_cert_trusted),
                          'sha1Fingerprint' : fingerprint,
                          'isExtendedValidation' : str(is_ev),
                          'hasMatchingHostname' : str(host_xml)}
        if untrusted_reason:
            trust_xml_attr['reasonWhyNotTrusted'] = untrusted_reason
            
        trust_xml = Element('certificate', attrib = trust_xml_attr)
        for elem_xml in cert_parsed.parse_certificate_to_xml():
            trust_xml.append(elem_xml)
        xml_result.append(trust_xml)
        
        ctSSL_cleanup()
        return PluginBase.PluginResult(txt_result, xml_result)


# FORMATTING FUNCTIONS

    def _is_hostname_valid(self, cert_dict, target):
        (host, ip, port) = target
        
        # Let's try the common name first
        commonName = cert_dict['subject']['commonName'][0]
        if _dnsname_to_pat(commonName).match(host):
            return 'Common Name'
        
        try: # No luch, let's look at Subject Alternative Names
            alt_names = cert_dict['extensions']['X509v3 Subject Alternative Name']['DNS']
        except KeyError:
            return False
        
        for altname in alt_names:
            if _dnsname_to_pat(altname).match(host):
                return 'Subject Alternative Name'       
        
        return False
        

    def _is_ev_certificate(self, cert_dict):
        try:
            policy = cert_dict['extensions']['X509v3 Certificate Policies']['Policy']
            if policy[0] in MOZILLA_EV_OIDS:
                return True
        except:
            return False
        return False
        
    
    def _get_basic_text(self, cert,  cert_dict):      
        basic_txt = [ \
        self.FIELD_FORMAT.format("Common Name:", cert_dict['subject']['commonName'][0] ),
        self.FIELD_FORMAT.format("Issuer:", cert.get_issuer_name().get_as_text()),
        self.FIELD_FORMAT.format("Serial Number:", cert_dict['serialNumber']),
        self.FIELD_FORMAT.format("Not Before:", cert_dict['validity']['notBefore']),
        self.FIELD_FORMAT.format("Not After:", cert_dict['validity']['notAfter']),
        self.FIELD_FORMAT.format("Signature Algorithm:", cert_dict['signatureAlgorithm']),
        self.FIELD_FORMAT.format("Key Size:", cert_dict['subjectPublicKeyInfo']['publicKeySize'])]
        
        try:
            alt_name = cert.get_extension_list().get_extension('X509v3 Subject Alternative Name')
            basic_txt.append (self.FIELD_FORMAT.format('X509v3 Subject Alternative Name:', alt_name))
        except KeyError:
            pass
        
        return basic_txt


    def _get_fingerprint(self, cert):
        nb = cert.get_fingerprint()
        val_txt = self.FIELD_FORMAT.format('SHA1 Fingerprint:', nb)
        val_xml = Element('fingerprint', algorithm='sha1')
        val_xml.text = nb
        return ([val_txt], [val_xml])    


    def _get_cert(self, target):
        """
        Connects to the target server and returns the server's certificate
        """
        verify_result = None
        ssl_ctx = SSL_CTX.SSL_CTX('tlsv1') # sslv23 hello will fail for specific servers such as post.craigslist.org
        ssl_ctx.load_verify_locations(MOZILLA_CA_STORE)
        ssl_ctx.set_verify(constants.SSL_VERIFY_NONE) # We'll use get_verify_result()
        ssl_connect = SSLyzeSSLConnection(self._shared_settings, target,ssl_ctx,
                                          hello_workaround=True)

        try: # Perform the SSL handshake
            ssl_connect.connect()
            cert = ssl_connect._ssl.get_peer_certificate()
            verify_result = ssl_connect._ssl.get_verify_result()
        finally:
            ssl_connect.close()

        return (cert, verify_result)


def _dnsname_to_pat(dn):
    """
    Generates a regexp for the given name, to be used for hostname validation
    Taken from http://pypi.python.org/pypi/backports.ssl_match_hostname/3.2a3
    """
    pats = []
    for frag in dn.split(r'.'):
        if frag == '*':
            # When '*' is a fragment by itself, it matches a non-empty dotless
            # fragment.
            pats.append('[^.]+')
        else:
            # Otherwise, '*' matches any dotless fragment.
            frag = re.escape(frag)
            pats.append(frag.replace(r'\*', '[^.]*'))
    return re.compile(r'\A' + r'\.'.join(pats) + r'\Z', re.IGNORECASE)
