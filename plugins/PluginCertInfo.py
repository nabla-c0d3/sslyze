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
from utils.SSLyzeSSLConnection import create_sslyze_connection, ClientAuthenticationError



# Import Mozilla trust store and EV OIDs
DATA_PATH = os.path.join(os.path.dirname(PluginBase.__file__) , 'data')
MOZILLA_CA_STORE = os.path.join(DATA_PATH, 'mozilla_cacert.pem')
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
            (cert, verifyStr) = self._get_cert(target)
        except:
            raise
        
        trustedCert = False
        if verifyStr in 'ok':
            trustedCert = True        
 
        # Results formatting
        cert_dict = cert.as_dict()
        
        # Text output
        if arg == 'basic':
            cert_txt = self._get_basic_text(cert_dict)
        elif arg == 'full':
            cert_txt = [cert.as_text()]
        else:
            raise Exception("PluginCertInfo: Unknown command.")
            
        fingerprint = cert.get_SHA1_fingerprint()
        cmd_title = 'Certificate'
        txt_result = [self.PLUGIN_TITLE_FORMAT(cmd_title)]
        
        if trustedCert:
            trust_txt = 'Certificate is Trusted'
        else:
            trust_txt = 'Certificate is NOT Trusted: ' + verifyStr

        is_ev = self._is_ev_certificate(cert_dict)
        if is_ev:
            trust_txt = trust_txt + ' - Extended Validation'

        txt_result.append(self.FIELD_FORMAT("Validation w/ Mozilla's CA Store:", trust_txt))
        
        # TODO: Use SNI name when --sni was used
        is_host_valid = self._is_hostname_valid(cert_dict, target)
        host_txt = 'OK - ' + is_host_valid + ' Matches' if is_host_valid \
                                         else 'MISMATCH'
        
        txt_result.append(self.FIELD_FORMAT("Hostname Validation:", host_txt))
        txt_result.append(self.FIELD_FORMAT('SHA1 Fingerprint:', fingerprint))
        txt_result.append('')
        txt_result.extend(cert_txt)

        # XML output: always return the full certificate
        host_xml = True if is_host_valid \
                        else False
            
        xml_result = Element(command, argument = arg, title = cmd_title)
        trust_xml_attr = {'isTrustedByMozillaCAStore' : str(trustedCert),
                          'sha1Fingerprint' : fingerprint,
                          'isExtendedValidation' : str(is_ev),
                          'hasMatchingHostname' : str(host_xml)}
        if verifyStr:
            trust_xml_attr['reasonWhyNotTrusted'] = verifyStr
            
        trust_xml = Element('certificate', attrib = trust_xml_attr)
        
        # Add certificate in PEM format
        PEMcert_xml = Element('asPEM')
        PEMcert_xml.text = cert.as_pem().strip()
        trust_xml.append(PEMcert_xml)
        
        for elem_xml in cert.as_xml():
            trust_xml.append(elem_xml)
        xml_result.append(trust_xml)
        
        return PluginBase.PluginResult(txt_result, xml_result)


# FORMATTING FUNCTIONS

    def _is_hostname_valid(self, cert_dict, target):
        (host, ip, port, sslVersion) = target
        
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
        
    
    def _get_basic_text(self, certDict):
        
        basicTxt = [ \
            self.FIELD_FORMAT("Common Name:", certDict['subject']['commonName']),
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
        Connects to the target server and returns the server's certificate
        """
        (host, ip, port, sslVersion) = target
        sslConn = create_sslyze_connection(self._shared_settings, sslVersion)#, 
#                                           sslVerifyLocations=MOZILLA_CA_STORE)
        
        try: # Perform the SSL handshake
            sslConn.connect((ip, port))

            x509Cert = sslConn.get_peer_certificate()
            (verifyCode, verifyStr) = sslConn.get_certificate_chain_verify_result()
        
        except ClientAuthenticationError: # The server asked for a client cert
            # We can get the server cert anyway
            x509Cert = sslConn.get_peer_certificate()
            (verifyCode, verifyStr) = sslConn.get_certificate_chain_verify_result()      
            
        finally:
            sslConn.close()

        return (x509Cert, verifyStr)


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
