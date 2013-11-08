#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginTrustTracker.py
# Purpose:      Verifies the validity of target server's certificate chain 
#               against multiple trust stores including Mozilla's, Microsoft's 
#               and Apple's trust stores."
#
# Author:       alban
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


from os.path import join, dirname, split
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.SSLyzeSSLConnection import create_sslyze_connection, ClientAuthenticationError

# Cross-plugin dependencies :s
from plugins.PluginCertInfo import _create_xml_node, _keyvalue_pair_to_xml


# All the trust store data is taken from the catt project hosted at
# https://github.com/kirei/catt
TRUST_STORES_PATH = join(join(dirname(PluginBase.__file__), 'data'), 'trust_stores')

AVAILABLE_TRUST_STORES = \
    { 'Mozilla NSS - 09/2013' : join(TRUST_STORES_PATH, 'mozilla.pem'),
      'Microsoft - 11/2013'   : join(TRUST_STORES_PATH, 'microsoft.pem'),
      'Apple - OS X 10.9.0'   : join(TRUST_STORES_PATH, 'apple.pem'),
      'Java 7 - Update 25'    : join(TRUST_STORES_PATH, 'java.pem')}

        
class PluginTrustTracker(PluginBase.PluginBase):
    interface = PluginBase.PluginInterface(title="PluginTrustTracker", description=(''))
    interface.add_command(
        command="track_trust",
        help= "Verifies the validity of target server's certificate chain against "
            "multiple trust stores including Mozilla's, Microsoft's and Apple's stores.",
        dest=None)

    FIELD_FORMAT = '      {0:<40}: {1}'.format
    TRUST_FORMAT =        '      \"{0}\" CA Store: {1}'.format
    

    def process_task(self, target, command, arg):

        verifyResults = {}
        # Try to connect using each available trust store and store the result
        for (trustStoreTitle, trustStorePath) in AVAILABLE_TRUST_STORES.items():
            (cert, verifyStr) = self._get_cert(target, trustStorePath)
            verifyResults[trustStoreTitle] = verifyStr

                
        # Results formatting
        # Text output - display each trust store and the validation result
        cmdTitle = 'Trust Tracker'
        txtOutput = [self.PLUGIN_TITLE_FORMAT(cmdTitle)]
        isCertTrustedByAll = True
        fingerprint = cert.get_SHA1_fingerprint()
        txtOutput.append(self.FIELD_FORMAT('Certificate SHA1 Fingerprint', fingerprint))
        # TODO: hostname validation
        txtOutput.append(self.FIELD_FORMAT('Hostname Validation', 'TBD'))
        
        for (trustStoreTitle, verifyStr) in verifyResults.items():
            if verifyStr != 'ok':
                isCertTrustedByAll = False
            txtOutput.append(self.FIELD_FORMAT('\"' + trustStoreTitle + '\" CA Store', verifyStr))


        # XML output
        xmlOutput = Element(command, title=cmdTitle)
        trustStoresXml = Element('trustStoreList', isTrustedByAllTrustStores = str(isCertTrustedByAll))
        
        for (trustStoreTitle, verifyStr) in verifyResults.items():
            # Add the result of each trust store
            trustStoresXml.append(Element('trustStore', 
                                          storeOrigin= trustStoreTitle, 
                                          verifyResult= verifyStr))
        xmlOutput.append(trustStoresXml)
        
        # Add the certificate
        certXml = Element('certificate', sha1Fingerprint=fingerprint)
        for (key, value) in cert.as_dict().items():
            certXml.append(_keyvalue_pair_to_xml(key, value))
            
        xmlOutput.append(certXml)
        
        return PluginBase.PluginResult(txtOutput, xmlOutput)


    def _get_cert(self, target, trustStorePath):
        """
        Connects to the target server and returns the server's certificate
        Also performs verification against multiple trust stores.
        """
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

        return (x509Cert, verifyStr)
    

