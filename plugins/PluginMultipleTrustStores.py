#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginMultipleTrustStores.py
# Purpose:      TBD
#
# Author:       alban, joachims
#
# Copyright:    2013 SSLyze developers
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
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.SSLyzeSSLConnection import create_sslyze_connection, ClientAuthenticationError

# Cross-plugin dependencies :s
from plugins.PluginCertInfo import _create_xml_node, _keyvalue_pair_to_xml


# Import all trust stores within the data path during module init
DATA_PATH = os.path.join(os.path.dirname(PluginBase.__file__) , 'data')
TRUST_STORE_PATHS = []
for filename in  os.listdir(DATA_PATH):
    if ".pem" in filename:
        TRUST_STORE_PATHS.append(os.path.join(DATA_PATH, filename))
        

class PluginMultipleTrustStores(PluginBase.PluginBase):
    interface = PluginBase.PluginInterface(title="PluginMultipleTrustStores", description=(''))
    interface.add_command(
        command="truststores",
        help= "Verifies the validity of target server's certificate chain against "
            "all the trust stores available as PEM files within ./plugins/data/.",
        dest=None)

    FIELD_FORMAT = '      {0:<40}{1}'.format
    
    def process_task(self, target, command, arg):

        # Get the certificate and validate it against all the trust stores
        (cert, verify_result) = self._get_cert(target, TRUST_STORE_PATHS)
                
        # Results formatting
        # Text output - display each trust store and the validation result
        cmdTitle = 'Multi Trust Store Validation'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]
        isCertTrusted = True
        fingerprint = cert.get_SHA1_fingerprint()
        txtOutput.append(self.FIELD_FORMAT('Certificate SHA1 Fingerprint:', fingerprint))
        
        for trustStorePath in TRUST_STORE_PATHS:
            if verify_result[trustStorePath] != 'ok':
                isCertTrusted = False
            txtOutput.append(self.FIELD_FORMAT("Validation w/ '" + 
                                               os.path.split(trustStorePath)[1]+ 
                                               "': ", verify_result[trustStorePath]))

        # XML output.
        xmlOutput = Element(command, title=cmdTitle)
        trustStoresXml = Element('trustStoreList', isTrustedByAllTrustStores = str(isCertTrusted))
        
        for trustStorePath in TRUST_STORE_PATHS:
            # Add the result of each trust store
            trustStoresXml.append(Element('trustStore', 
                                          filePath=os.path.split(trustStorePath)[1], 
                                          verifyResult= verify_result[trustStorePath]))
        xmlOutput.append(trustStoresXml)
        
        # Add the certificate
        certXml = Element('certificate', sha1Fingerprint=fingerprint)
        for (key, value) in cert.as_dict().items():
            certXml.append(_keyvalue_pair_to_xml(key, value))
            
        xmlOutput.append(certXml)
        
        return PluginBase.PluginResult(txtOutput, xmlOutput)


    def _get_cert(self, target, trustStoreList):
        """
        Connects to the target server and returns the server's certificate
        Also performs verification against multiple trust stores.
        """
        verifyResults = {}
        for trustStorePath in trustStoreList:
            
            (host, ip, port, sslVersion) = target
            sslConn = create_sslyze_connection(target, self._shared_settings, 
                                               sslVersion, 
                                               sslVerifyLocations=trustStorePath)
            
            try:
                # Perform the SSL handshake
                sslConn.connect()
                x509Cert = sslConn.get_peer_certificate()
                (verifyCode, verifyStr) = sslConn.get_certificate_chain_verify_result()
            
            except ClientCertificateError:
                # The server asked for a client cert
                # We can get the server cert anyway
                x509Cert = sslConn.get_peer_certificate()
                (verifyCode, verifyStr) = sslConn.get_certificate_chain_verify_result()          
            
            finally:
                sslConn.close()

            verifyResults[trustStorePath] = verifyStr

        return (x509Cert, verifyResults)
    

