#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginChromeSha1Deprecation.py
# Purpose:      Determines if the certificate will be affected by Google 
#               Chrome's SHA-1 Deprecation plans
#
# Author:       tritter, alban
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


from xml.etree.ElementTree import Element
import base64
import hashlib
import datetime

from plugins import PluginBase
from utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl.SslClient import ClientCertificateRequested

# We have to import it this way or PluginCertInfo gets detected twice by SSLyze on Linux
import plugins.PluginCertInfo
from plugins.PluginCertInfo import MOZILLA_STORE_PATH, PluginCertInfo

ROOT_CERTS = []


class PluginChromeSha1Deprecation(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginChromeSha1Deprecation", description=(''))
    interface.add_command(
        command = "chrome_sha1",
        help = "Determines if the server will be affected by Google Chrome's SHA-1 deprecation plans. See "
    "http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html for more information")


    CMD_TITLE = "Google Chrome SHA-1 Deprecation Status"

    # Chrome icon descriptions
    CHROME_MINOR_ERROR_TXT = 'AFFECTED - SHA1-signed certificate(s) will trigger the "Secure, but minor errors" icon.'
    CHROME_NEUTRAL_TXT = 'AFFECTED - SHA1-signed certificate(s) will trigger the "Neutral, lacking security" icon.'
    CHROME_INSECURE_TXT = 'AFFECTED - SHA1-signed certificate(s) will trigger the "Affirmatively insecure" icon.'


    def process_task(self, target, command, arg):

        (_, _, _, sslVersion) = target

        # Get the server's cert chain
        sslConn = create_sslyze_connection(target, self._shared_settings, sslVersion)
        try: # Perform the SSL handshake
            sslConn.connect()
            certChain = sslConn.get_peer_cert_chain()
        except ClientCertificateRequested: # The server asked for a client cert
            # We can get the server cert chain anyway
            certChain = sslConn.get_peer_cert_chain()
        finally:
            sslConn.close()

        outputXml = Element(command, title = self.CMD_TITLE)
        outputTxt = [self.PLUGIN_TITLE_FORMAT(self.CMD_TITLE)]

        # Is this cert chain affected ?
        leafNotAfter = datetime.datetime.strptime(certChain[0].as_dict()['validity']['notAfter'], "%b %d %H:%M:%S %Y %Z")
        if leafNotAfter.year < 2016:
            # Not affected - the certificate expires before 2016
            outputTxt.append(self.FIELD_FORMAT('OK - Leaf certificate expires before 2016.', ''))
            outputXml.append(Element('chromeSha1Deprecation', isServerAffected = str(False)))

        else:
            certsWithSha1 = []
            for cert in certChain:
                if self._is_root_cert(cert):
                    # Ignore root certs as they are unaffected
                    continue

                if "sha1" in cert.as_dict()['signatureAlgorithm']:
                    certsWithSha1.append(cert)

            if certsWithSha1 == []:
                # Not affected - no certificates used SHA-1 in the chain
                outputTxt.append(self.FIELD_FORMAT('OK - Certificate chain does not contain any SHA-1 certificate.', ''))
                outputXml.append(Element('chromeSha1Deprecation', isServerAffected = str(False)))

            else:
                # Server is affected
                leafCertNotAfter = certChain[0].as_dict()['validity']['notAfter']
                outputXml2 = Element('chromeSha1Deprecation', isServerAffected = str(True),
                                     leafCertificateNotAfter = leafCertNotAfter)
                chrome39Txt = 'OK'
                chrome40Txt = 'OK'

                if leafNotAfter.year == 2016 and leafNotAfter.month < 6:
                    chrome41Txt = self.CHROME_MINOR_ERROR_TXT


                elif leafNotAfter.year == 2016 and leafNotAfter.month >= 6:
                    chrome40Txt = self.CHROME_MINOR_ERROR_TXT
                    chrome41Txt = self.CHROME_MINOR_ERROR_TXT

                else:
                    # Certificate expires in 2017
                    chrome39Txt = self.CHROME_MINOR_ERROR_TXT
                    chrome40Txt = self.CHROME_NEUTRAL_TXT
                    chrome41Txt = self.CHROME_INSECURE_TXT

                # Text output
                certsWithSha1Txt = ['"{0}"'.format(PluginCertInfo._extract_subject_CN_or_OUN(cert)) for cert in certsWithSha1]
                outputTxt.append(self.FIELD_FORMAT("Chrome 39 behavior:", chrome39Txt))
                outputTxt.append(self.FIELD_FORMAT("Chrome 40 behavior:", chrome40Txt))
                outputTxt.append(self.FIELD_FORMAT("Chrome 41 behavior:", chrome41Txt))
                outputTxt.append(self.FIELD_FORMAT("Leaf certificate notAfter field:", leafCertNotAfter))
                outputTxt.append(self.FIELD_FORMAT("SHA1-signed certificates:", certsWithSha1Txt))

                # XML output
                affectedCertsXml = Element('sha1SignedCertificates')
                for cert in certsWithSha1:
                    affectedCertsXml.append(PluginCertInfo._format_cert_to_xml(cert, '', self._shared_settings['sni']))
                outputXml2.append(affectedCertsXml)

                outputXml2.append(Element(
                    'chrome39',
                    behavior = chrome39Txt,
                    isAffected = str(False) if chrome39Txt is 'OK' else str(True)))
                outputXml2.append(Element(
                    'chrome40',
                    behavior = chrome40Txt,
                    isAffected = str(False) if chrome40Txt is 'OK' else str(True)))
                outputXml2.append(Element(
                    'chrome41',
                    behavior = chrome41Txt,
                    isAffected = str(True)))
                outputXml.append(outputXml2)
        
        return PluginBase.PluginResult(outputTxt, outputXml)


    @staticmethod
    def _is_root_cert(cert):
        # Root certificates are not affected by the deprecation of SHA1
        # However a properly configured server should not send the CA cert in the chain so I'm not using this for now
        if not ROOT_CERTS:
            #Parse the Mozilla Store into roots
            f = open(MOZILLA_STORE_PATH, 'r')
            f_contents = "\n".join(f.readlines())
            root_certs = f_contents.split("-----BEGIN CERTIFICATE-----")
            for r in root_certs:
                if not r.strip():
                    continue
                r = r.replace("-----END CERTIFICATE-----", "")
                r = r.replace("\n", "")
                r = r.replace("\r", "")
                d = base64.b64decode(r)
                ROOT_CERTS.append(hashlib.sha1(d).hexdigest())
        return cert.get_SHA1_fingerprint() in ROOT_CERTS