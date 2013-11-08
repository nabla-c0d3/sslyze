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
import imp
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.SSLyzeSSLConnection import create_sslyze_connection, ClientAuthenticationError



# Import Mozilla trust store and EV OIDs
DATA_PATH = os.path.join(os.path.dirname(PluginBase.__file__) , 'data')
MOZILLA_CA_STORE = os.path.join(DATA_PATH, os.path.join('trust_stores', 'mozilla.pem'))
MOZILLA_EV_OIDS = imp.load_source('mozilla_ev_oids',
                                  os.path.join(DATA_PATH,  'mozilla_ev_oids.py')).MOZILLA_EV_OIDS


        
class PluginCertInfo(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCertInfo", description=(''))
    interface.add_command(
        command="certinfo",
        help= "Verifies the target server's certificate validity against "
            "Mozilla's trusted root store, and prints relevant fields of "
            "the certificate. CERTINFO should be 'basic' or 'full'.",
        dest="certinfo")

    FIELD_FORMAT = '      {0:<35}{1:<35}'.format
    

    def process_task(self, target, command, arg):

        try: # Get the certificate and the result of the cert validation
            (cert, certVerifyStr, ocspResp) = self._get_cert(target)
        except:
            raise
        
        trustedCert = True if 'ok' in certVerifyStr else False
 
        # Results formatting
        # Text output - certificate
        txt_result = [self.PLUGIN_TITLE_FORMAT('Certificate')]
        
        if arg == 'basic':
            cert_txt = self._get_basic_text(cert)
        elif arg == 'full':
            cert_txt = [cert.as_text()]
        else:
            raise Exception("PluginCertInfo: Unknown command.")
            
        fingerprint = cert.get_SHA1_fingerprint()
        
        # Cert chain validation
        trust_txt = 'Certificate is Trusted' if trustedCert \
            else 'Certificate is NOT Trusted: ' + certVerifyStr

        is_ev = self._is_ev_certificate(cert)
        if is_ev:
            trust_txt = trust_txt + ' - Extended Validation'
            
       # Hostname validation
        if self._shared_settings['sni']:
           txt_result.append(self.FIELD_FORMAT("SNI enabled with virtual domain:", 
                                               self._shared_settings['sni'])) 
        txt_result.append(self.FIELD_FORMAT("Validation w/ Mozilla's CA Store:", trust_txt))
        
        # TODO: Use SNI name when --sni was used
        is_host_valid = self._is_hostname_valid(cert, target)
        host_txt = 'OK - ' + is_host_valid + ' Matches' if is_host_valid \
                                         else 'MISMATCH'
        
        txt_result.append(self.FIELD_FORMAT("Hostname Validation:", host_txt))
        txt_result.append(self.FIELD_FORMAT('SHA1 Fingerprint:', fingerprint))
        txt_result.append('')
        txt_result.extend(cert_txt)

        # Text output - OCSP stapling
        txt_result.append('')
        txt_result.append(self.PLUGIN_TITLE_FORMAT('OCSP Stapling'))
        txt_result.extend(self._get_ocsp_text(ocspResp))


        # XML output: always return the full certificate
        host_xml = True if is_host_valid \
                        else False
            
        xml_result = Element(command, argument = arg, title = 'Certificate')
        trust_xml_attr = {'isTrustedByMozillaCAStore' : str(trustedCert),
                          'sha1Fingerprint' : fingerprint,
                          'isExtendedValidation' : str(is_ev),
                          'hasMatchingHostname' : str(host_xml)}
        if certVerifyStr:
            trust_xml_attr['reasonWhyNotTrusted'] = certVerifyStr
        
        if self._shared_settings['sni']:
            trust_xml_attr['sni'] = self._shared_settings['sni'] 
            
        trust_xml = Element('certificate', attrib = trust_xml_attr)
        
        # Add certificate in PEM format
        PEMcert_xml = Element('asPEM')
        PEMcert_xml.text = cert.as_pem().strip()
        trust_xml.append(PEMcert_xml)

        for (key, value) in cert.as_dict().items():
            trust_xml.append(_keyvalue_pair_to_xml(key, value))
            
        xml_result.append(trust_xml)
        
        # XML output: OCSP Stapling
        if ocspResp is None:
            oscpAttr =  {'error' : 'Server did not send back an OCSP response'}
            ocspXml = Element('ocspStapling', attrib = oscpAttr)
        else:
            oscpAttr =  {'isTrustedByMozillaCAStore' : str(ocspResp.verify(MOZILLA_CA_STORE))}
            ocspXml = Element('ocspResponse', attrib = oscpAttr)

            for (key, value) in ocspResp.as_dict().items():
                ocspXml.append(_keyvalue_pair_to_xml(key,value))
                
        xml_result.append(ocspXml)        
        
        return PluginBase.PluginResult(txt_result, xml_result)


# FORMATTING FUNCTIONS

    def _get_ocsp_text(self, ocspResp):
        
        if ocspResp is None:
            return [self.FIELD_FORMAT('Server did not send back an OCSP response.', '')]
        
        ocspRespDict = ocspResp.as_dict()
        ocspRespTrustTxt = 'Response is Trusted' if ocspResp.verify(MOZILLA_CA_STORE) \
            else 'Response is NOT Trusted'
        
        ocspRespTxt = [ \
            self.FIELD_FORMAT('OCSP Response Status:', ocspRespDict['responseStatus']),
            self.FIELD_FORMAT('Validation w/ Mozilla\'s CA Store:', ocspRespTrustTxt),
            self.FIELD_FORMAT('Responder Id:', ocspRespDict['responderID'])]
        
        if 'successful' not in ocspRespDict['responseStatus']:
            return ocspRespTxt

        ocspRespTxt.extend( [ \
            self.FIELD_FORMAT('Cert Status:', ocspRespDict['responses'][0]['certStatus']),
            self.FIELD_FORMAT('Cert Serial Number:', ocspRespDict['responses'][0]['certID']['serialNumber']),
            self.FIELD_FORMAT('This Update:', ocspRespDict['responses'][0]['thisUpdate']),
            self.FIELD_FORMAT('Next Update:', ocspRespDict['responses'][0]['nextUpdate'])])
        
        return ocspRespTxt

    
    @staticmethod
    def _is_hostname_valid(cert, target):
        (host, ip, port, sslVersion) = target
        
        if cert._matches_CN(host):
            return 'Common Name'

        if cert._matches_subject_alt_name(host):
            return 'Subject Alternative Name' 

        return False
        
    
    @staticmethod
    def _is_ev_certificate(cert):
        certDict = cert.as_dict()
        try:
            policy = certDict['extensions']['X509v3 Certificate Policies']['Policy']
            if policy[0] in MOZILLA_EV_OIDS:
                return True
        except:
            return False
        return False
        
    
    def _get_basic_text(self, cert):
        certDict = cert.as_dict()

        try: # Extract the CN if there's one
            commonName = certDict['subject']['commonName']
        except KeyError:
            commonName = 'None'
        
        basicTxt = [ \
            self.FIELD_FORMAT("Common Name:", commonName),
            self.FIELD_FORMAT("Issuer:", certDict['issuer']),
            self.FIELD_FORMAT("Serial Number:", certDict['serialNumber']),
            self.FIELD_FORMAT("Not Before:", certDict['validity']['notBefore']),
            self.FIELD_FORMAT("Not After:", certDict['validity']['notAfter']),
            self.FIELD_FORMAT("Signature Algorithm:", certDict['signatureAlgorithm']),
            self.FIELD_FORMAT("Key Size:", certDict['subjectPublicKeyInfo']['publicKeySize'])]
        
        try: # Print the SAN extension if there's one
            basicTxt.append(self.FIELD_FORMAT('X509v3 Subject Alternative Name:', 
                                              certDict['extensions']['X509v3 Subject Alternative Name']))
        except KeyError:
            pass
        
        return basicTxt


    def _get_fingerprint(self, cert):
        nb = cert.get_SHA1_fingerprint()
        val_txt = self.FIELD_FORMAT('SHA1 Fingerprint:', nb)
        val_xml = Element('fingerprint', algorithm='sha1')
        val_xml.text = nb
        return ([val_txt], [val_xml])    


    def _get_cert(self, target):
        """
        Connects to the target server and returns the server's certificate and
        OCSP response.
        """
        (host, ip, port, sslVersion) = target
        sslConn = create_sslyze_connection(target, self._shared_settings, sslVersion, 
                                           sslVerifyLocations=MOZILLA_CA_STORE)
        
        # Enable OCSP stapling
        sslConn.set_tlsext_status_ocsp()
        
        try: # Perform the SSL handshake
            sslConn.connect()
            
            ocspResp = sslConn.get_tlsext_status_ocsp_resp()
            x509Cert = sslConn.get_peer_certificate()
            (verifyCode, verifyStr) = sslConn.get_certificate_chain_verify_result()
        
        except ClientAuthenticationError: # The server asked for a client cert
            # We can get the server cert anyway
            ocspResp = sslConn.get_tlsext_status_ocsp_resp()
            x509Cert = sslConn.get_peer_certificate()
            (verifyCode, verifyStr) = sslConn.get_certificate_chain_verify_result()      
            
        finally:
            sslConn.close()

        return (x509Cert, verifyStr, ocspResp)


# XML generation
def _create_xml_node(key, value=''):
    key = key.replace(' ', '').strip() # Remove spaces
    key = key.replace('/', '').strip() # Remove slashes (S/MIME Capabilities)
    
    # Things that would generate invalid XML
    if key[0].isdigit(): # Tags cannot start with a digit
            key = 'oid-' + key 
            
    xml_node = Element(key)
    xml_node.text = value.decode( "utf-8" ).strip()
    return xml_node


def _keyvalue_pair_to_xml(key, value=''):
    
    if type(value) is str: # value is a string
        key_xml = _create_xml_node(key, value)

    elif type(value) is int:
        key_xml = _create_xml_node(key, str(value))
        
    elif value is None: # no value
        key_xml = _create_xml_node(key)
       
    elif type(value) is list: 
        key_xml = _create_xml_node(key)
        for val in value:
            key_xml.append(_keyvalue_pair_to_xml('listEntry', val))
       
    elif type(value) is dict: # value is a list of subnodes
        key_xml = _create_xml_node(key)
        for subkey in value.keys():
            key_xml.append(_keyvalue_pair_to_xml(subkey, value[subkey]))
    else:
        raise Exception()
        
    return key_xml    

