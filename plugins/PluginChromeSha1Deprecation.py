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
import dateutil.parser, base64, hashlib

from plugins import PluginBase
from utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl.SslClient import ClientCertificateRequested
from PluginCertInfo import MOZILLA_STORE_PATH

ROOT_CERTS = []

class PluginChromeSha1Deprecation(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginChromeSha1Deprecation", description=(''))
    interface.add_command(
        command = "chrome_sha1",
        help = "Determines if the server will be affected by Google Chrome's SHA-1 deprecation plans. See "
    "http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html for more information")

    def process_task(self, target, command, arg):
        OUT_FORMAT = '      {0:<35}{1}'.format
        CMDTITLE="Google Chrome SHA-1 Deprecation Status"

        (_, _, _, sslVersion) = target

        # =====================================================================
        # Cert Cert Chain
        sslConn = create_sslyze_connection(target, self._shared_settings, sslVersion)
        try: # Perform the SSL handshake
            sslConn.connect()
            leaf = sslConn.get_peer_certificate()
            certs = sslConn.get_peer_cert_chain()
        except ClientCertificateRequested: # The server asked for a client cert
            # We can get the server cert anyway
            leaf = sslConn.get_peer_certificate()
            certs = sslConn.get_peer_cert_chain()
        finally:
            sslConn.close()

        # =====================================================================
        # Process Certs
        sawRoot = False
        leafIsLongLived = False
        a2016_h1 = False
        a2016_h2 = False
        a2016 = False
        a2017 = False
        sha1s = []

        certDict = leaf.as_dict()
        notAfter = dateutil.parser.parse(certDict['validity']['notAfter'])
        if notAfter.year >= 2016:
            leafIsLongLived = True
        if notAfter.year == 2016:
            if notAfter.month < 6:
                a2016_h1 = True
            else:
                a2016_h2 = True
        if notAfter.year >= 2017:
            a2017 = True
        a2016 = a2016_h1 or a2016_h2

        for c in certs:
            if self._is_root_cert(c):
                if sawRoot:
                    raise Exception("Saw two root certificates?!")
                sawRoot = True
                continue

            #Only care about SHA-1's if the cert is long-lived
            if leafIsLongLived:
                certDict = c.as_dict()
                if "sha1" in certDict['signatureAlgorithm']:
                    sha1s.append(c)
                else:
                    continue

        # =====================================================================
        # Results formatting
        # Text output - certificate info
        xmlOutput = Element(command, title=CMDTITLE)
        outputTxt = [self.PLUGIN_TITLE_FORMAT(CMDTITLE)]


        # =====================================================================
        # M39
        if not leafIsLongLived:
            status = "Not Affected (Leaf certificate expires before 2016)"
        elif leafIsLongLived and not sha1s:
            status = "Not Affected (Long lived leaf certificate, but no SHA-1 certificates in chain)"

        elif a2017 and sha1s:
            status = "Affected (" + str(len(sha1s)) + \
                " Cert" + ("s" if len(sha1s) > 1 else "") + " will trigger 'Secure, but minor errors' icon)"
        elif a2016:
            status = "Not Affected (Leaf certificate expires in 2016)"
        else:
            status = "ohshit1"
        outputTxt.append(OUT_FORMAT("Chrome 39 Behavior:", status))
        xmlNode = Element('chome39status', value=status)
        xmlOutput.append(xmlNode)
        
        # =====================================================================
        # M40
        if not leafIsLongLived:
            status = "Not Affected (Leaf certificate expires before 2016)"
        elif leafIsLongLived and not sha1s:
            status = "Not Affected (Long lived leaf certificate, but no SHA-1 certificates in chain)"

        elif a2017 and sha1s:
            status = "Affected (" + str(len(sha1s)) + \
                " Cert" + ("s" if len(sha1s) > 1 else "") + " will trigger 'Neutral, no security' icon)"
        elif a2016_h2:
            status = "Affected (" + str(len(sha1s)) + \
                " Cert" + ("s" if len(sha1s) > 1 else "") + " will trigger 'Secure, but minor errors' icon)"
        elif a2016_h1:
            status = "Not Affected (Leaf certificate expires in first half of 2016)"
        else:
            status = "ohshit2"
        outputTxt.append(OUT_FORMAT("Chrome 40 Behavior:", status))
        xmlNode = Element('chome40status', value=status)
        xmlOutput.append(xmlNode)

        # =====================================================================
        # M41
        if not leafIsLongLived:
            status = "Not Affected (Leaf certificate expires before 2016)"
        elif leafIsLongLived and not sha1s:
            status = "Not Affected (Long lived leaf certificate, but no SHA-1 certificates in chain)"
        
        elif a2017 and sha1s:
            status = "Affected (" + str(len(sha1s)) + \
                " Cert" + ("s" if len(sha1s) > 1 else "") + " will trigger 'Lock with Red X' icon  and Mixed Content causes such an icon)"
        elif a2016 and sha1s:
            status = "Affected (" + str(len(sha1s)) + \
                " Cert" + ("s" if len(sha1s) > 1 else "") + " will trigger 'Secure, but minor errors' icon  and Mixed Content causes such an icon)"
        else:
            status = "ohshit3"
        outputTxt.append(OUT_FORMAT("Chrome 41 Behavior:", status))
        xmlNode = Element('chome41status', value=status)
        xmlOutput.append(xmlNode)

        # =====================================================================
        # Supplemental Data
        outputTxt.append(OUT_FORMAT("Certificate Chain:", str(len(certs)) + " Certificate" + ("s" if len(certs) > 1 else "") + (", 1 of which is a Root" if sawRoot else "")))
        outputTxt.append(OUT_FORMAT("Leaf Certificate notAfter:", str(notAfter.month) + "/" + str(notAfter.year)))

        if leafIsLongLived and sha1s:
            outputTxt.append(OUT_FORMAT("SHA-1 Certs:", ", ".join([c.get_SHA1_fingerprint()+":"+c.as_dict()['serialNumber'] for c in sha1s])))
            xmlNode = Element('sha-1_certs', value=", ".join([c.get_SHA1_fingerprint()+":"+c.as_dict()['serialNumber'] for c in sha1s]))
            xmlOutput.append(xmlNode)

        
        return PluginBase.PluginResult(outputTxt, xmlOutput)


    @staticmethod
    def _is_root_cert(cert):
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
