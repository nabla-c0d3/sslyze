#!/usr/bin/env python
# encoding: utf-8
#-------------------------------------------------------------------------------
# Name:         PluginRFC7465.py
# Purpose:      Checks if the target server compliants RFC7465 (no RC4)
#
# Author:       bluec0re
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

from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.SSLyzeSSLConnection import create_sslyze_connection, SSLHandshakeRejected
from nassl import SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2
from nassl.SslClient import SslClient


class PluginRFC7465(PluginBase.PluginBase):


    interface = PluginBase.PluginInterface(
        "PluginRFC7465",
        "Checks if the target server compliants RFC7465 (no RC4).")
    interface.add_command(
        command="rfc7465",
        help="Checks if the server violates RFC7465 and uses RC4 ciphers for negotiation")

    SSL_VERSIONS = {
        TLSV1: 'TLSV1',
        TLSV1_1: 'TLSV1_1',
        TLSV1_2: 'TLSV1_2'
    }


    def process_task(self, target, command, args):

        MAX_THREADS = 15
        sslVersions = self.SSL_VERSIONS.keys()
        cipher_list = []
        for sslVersion in sslVersions:
            # Get the list of available cipher suites for the given ssl version
            sslClient = SslClient(sslVersion=sslVersion)
            sslClient.set_cipher_list('RC4')
            cipher_list.append((sslVersion, sslClient.get_cipher_list()))

        # Create a thread pool
        NB_THREADS = min(sum(map(lambda x: len(x[1]), cipher_list)), MAX_THREADS) # One thread per cipher
        thread_pool = ThreadPool()

        # Scan for every available cipher suite
        for sslVersion, clist in cipher_list:
            for cipher in clist:
                thread_pool.add_job((self._test_ciphersuite,
                                    (target, sslVersion, cipher)))

        # Start processing the jobs
        thread_pool.start(NB_THREADS)

        result_dicts = {'acceptedCipherSuites':dict([(sv, {}) for sv in sslVersions]),
                        'rejectedCipherSuites':dict([(sv, {}) for sv in sslVersions]),
                        'errors':dict([(sv, {}) for sv in sslVersions])}

        # Store the results as they come
        for completed_job in thread_pool.get_result():
            (job, result) = completed_job
            if result is not None:
                (result_type, ssl_version, ssl_cipher, keysize, dh_infos, msg) = result
                (result_dicts[result_type])[ssl_version][ssl_cipher] = (msg, keysize, dh_infos)

        # Store thread pool errors
        for failed_job in thread_pool.get_error():
            (job, exception) = failed_job
            ssl_version = str(job[1][2])
            ssl_cipher = str(job[1][3])
            error_msg = str(exception.__class__.__name__) + ' - ' + str(exception)
            result_dicts['errors'][ssl_version][ssl_cipher] = (error_msg, None, None)

        thread_pool.join()

        # Generate results
        return PluginBase.PluginResult(self._generate_text_output(result_dicts),
                                       self._generate_xml_output(result_dicts))


# == INTERNAL FUNCTIONS ==

# FORMATTING FUNCTIONS
    def _generate_text_output(self, resultDicts):

        cipherFormat   = '                 {0:<32}    {1:<35}'.format
        titleFormat   =  '      {0:<32} '.format
        versionFormat =  '           {0:<32} '.format
        keysizeFormat = '{0:<30}{1:<15}{2:<10}'.format

        txtTitle = self.PLUGIN_TITLE_FORMAT('RFC7465 compliance')
        txtOutput = []

        dictTitles = [('acceptedCipherSuites', 'Accepted RC4 Ciphers:'),
                      ('errors', 'Undefined - An unexpected error happened:')]

        isViolating = False

        for (resultKey, resultTitle) in dictTitles:
            isFirst = True
            for sslVersion, results in resultDicts[resultKey].iteritems():
                sslVersion = PluginRFC7465.SSL_VERSIONS[sslVersion]
                # Sort the cipher suites by results
                result_list = sorted(results.iteritems(),
                                     key=lambda (k,v): (v,k), reverse=True)

                # Add a new line and title
                if len(result_list) == 0: # No ciphers
                    pass # Hide empty results
                else:
                    isViolating = True
                    if isFirst:
                        txtOutput.append(titleFormat(resultTitle))
                        isFirst = False
                    txtOutput.append(versionFormat(sslVersion))
                    # Add one line for each ciphers
                    for (cipherTxt, (msg, keysize, dh_infos)) in result_list:
                        if keysize:
                            if 'ADH' in cipherTxt or 'AECDH' in cipherTxt:
                                # Always display ANON as the key size for anonymous ciphers to make it visible
                                keysizeStr = 'ANONYMOUS'
                            else:
                                keysizeStr = str(keysize) + ' bits'

                            if dh_infos :
                                cipherTxt = keysizeFormat(cipherTxt, "%s-%s bits"%(dh_infos["Type"], dh_infos["GroupSize"]), keysizeStr)
                            else :
                                cipherTxt = keysizeFormat(cipherTxt, "-",  keysizeStr)

                        txtOutput.append(cipherFormat(cipherTxt, msg))
        if not isViolating:
            # Server rejected all cipher suites
            txtOutput = [txtTitle, '      OK - Server rejects RC4 ciphers.']
        else:
            txtOutput.insert(0,    '      FAIL - Server accepts RC4 ciphers.')
            txtOutput.insert(1,    '')
            txtOutput = [txtTitle] + txtOutput


        return txtOutput


    @staticmethod
    def _generate_xml_output(result_dicts):

        xmlNodeList = []
        isViolating = False

        for (resultKey, resultDict) in result_dicts.items():
            xmlNode1 = Element(resultKey)
            for sslVersion, results in resultDict.iteritems():
                sslVersion = PluginRFC7465.SSL_VERSIONS[sslVersion]
                xmlNode = Element(sslVersion)

                # Sort the cipher suites by name to make the XML diff-able
                resultList = sorted(results.iteritems(), key=lambda (k,v): (k,v), reverse=False)

                # Add one element for each ciphers
                for (sslCipher, (msg, keysize, dh_infos)) in resultList:

                    # The protocol is supported if at least one cipher suite was successfully negotiated
                    if resultKey == 'acceptedCipherSuites':
                        isViolating = True

                    cipherXmlAttr = {'name' : sslCipher, 'connectionStatus' : msg}
                    if keysize:
                        cipherXmlAttr['keySize'] = str(keysize)

                    # Add an Anonymous attribute for anonymous ciphers
                    cipherXmlAttr['anonymous'] = str(True) if 'ADH' in sslCipher or 'AECDH' in sslCipher else str(False)

                    cipherXml = Element('cipherSuite', attrib = cipherXmlAttr)
                    if dh_infos :
                        cipherXml.append(Element('keyExchange', attrib=dh_infos))


                    xmlNode.append(cipherXml)

                xmlNode1.append(xmlNode)

            xmlNodeList.append(xmlNode1)

        # Create the final node and specify if the protocol was supported
        xmlOutput = Element('rfc7465', title='RFC7465 compliance', isViolating=str(isViolating))
        for xmlNode in xmlNodeList:
            xmlOutput.append(xmlNode)

        return xmlOutput


# SSL FUNCTIONS
    def _test_ciphersuite(self, target, ssl_version, ssl_cipher):
        """
        Initiates a SSL handshake with the server, using the SSL version and
        cipher suite specified.
        """
        sslConn = create_sslyze_connection(target, self._shared_settings, ssl_version)
        sslConn.set_cipher_list(ssl_cipher)

        try: # Perform the SSL handshake
            sslConn.connect()

        except SSLHandshakeRejected as e:
            return 'rejectedCipherSuites', ssl_version, ssl_cipher, None, None, str(e)

        except:
            raise

        else:
            ssl_cipher = sslConn.get_current_cipher_name()
            keysize = sslConn.get_current_cipher_bits()

            if 'ECDH' in ssl_cipher :
                dh_infos = sslConn.get_ecdh_param()
            elif 'DH' in ssl_cipher :
                dh_infos = sslConn.get_dh_param()
            else :
                dh_infos = None
            status_msg = sslConn.post_handshake_check()
            return 'acceptedCipherSuites', ssl_version, ssl_cipher, keysize, dh_infos, status_msg

        finally:
            sslConn.close()
