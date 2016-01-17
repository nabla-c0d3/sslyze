#!/usr/bin/env python2.7
#-------------------------------------------------------------------------------
# Name:         PluginOpenSSLCipherSuites.py
# Purpose:      Scans the target server for supported OpenSSL cipher suites.
#
# Author:       alban
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

from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.SSLyzeSSLConnection import SSLHandshakeRejected
from nassl import SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2
from nassl.SslClient import SslClient


class PluginOpenSSLCipherSuites(PluginBase.PluginBase):


    interface = PluginBase.PluginInterface(
        "PluginOpenSSLCipherSuites",
        "Scans the server(s) for supported OpenSSL cipher suites.")
    interface.add_command(
        command="sslv2",
        help="Lists the SSL 2.0 OpenSSL cipher suites supported by the server(s).",
        aggressive=False
    )
    interface.add_command(
        command="sslv3",
        help="Lists the SSL 3.0 OpenSSL cipher suites supported by the server(s).",
        aggressive=True
    )
    interface.add_command(
        command="tlsv1",
        help="Lists the TLS 1.0 OpenSSL cipher suites supported by the server(s).",
        aggressive=True
    )
    interface.add_command(
        command="tlsv1_1",
        help="Lists the TLS 1.1 OpenSSL cipher suites supported by the server(s).",
        aggressive=True
    )
    interface.add_command(
        command="tlsv1_2",
        help="Lists the TLS 1.2 OpenSSL cipher suites supported by the server(s).",
        aggressive=True
    )
    interface.add_option(
        option='http_get',
        help="Option - For each cipher suite, sends an HTTP GET request after "
        "completing the SSL handshake and returns the HTTP status code."
    )
    interface.add_option(
        option='hide_rejected_ciphers',
        help="Option - Hides the (usually long) list of cipher suites that were"
        " rejected by the server(s)."
    )


    def process_task(self, server_connectivity_info, command, args):

        MAX_THREADS = 15
        ssl_version_dict = {'sslv2': SSLV2,
                            'sslv3': SSLV3,
                            'tlsv1': TLSV1,
                            'tlsv1_1': TLSV1_1,
                            'tlsv1_2': TLSV1_2}
        try:
            ssl_version = ssl_version_dict[command]
        except KeyError:
            raise ValueError("PluginOpenSSLCipherSuites: Unknown command.")

        # Get the list of available cipher suites for the given ssl version
        ssl_client = SslClient(ssl_version=ssl_version)
        ssl_client.set_cipher_list('ALL:COMPLEMENTOFALL')
        cipher_list = ssl_client.get_cipher_list()

        # Create a thread pool
        thread_pool = ThreadPool()

        # Scan for every available cipher suite
        for cipher in cipher_list:
            thread_pool.add_job((self._test_ciphersuite, (server_connectivity_info, ssl_version, cipher)))

        # Scan for the preferred cipher suite
        thread_pool.add_job((self._pref_ciphersuite, (server_connectivity_info, ssl_version)))

        # Start processing the jobs
        thread_pool.start(nb_threads=min(len(cipher_list), MAX_THREADS))  # One thread per cipher

        result_dicts = {'preferredCipherSuite':{}, 'acceptedCipherSuites':{}, 'rejectedCipherSuites':{}, 'errors':{}}

        # Store the results as they come
        for completed_job in thread_pool.get_result():
            (job, result) = completed_job
            if result is not None:
                (result_type, ssl_cipher, keysize, dh_infos, msg) = result
                (result_dicts[result_type])[ssl_cipher] = (msg, keysize, dh_infos)

        # Store thread pool errors
        for failed_job in thread_pool.get_error():
            (job, exception) = failed_job
            print job
            print exception
            ssl_cipher = str(job[1][2])
            error_msg = str(exception.__class__.__name__) + ' - ' + str(exception)
            result_dicts['errors'][ssl_cipher] = (error_msg, None, None)

        thread_pool.join()

        # Generate results
        return PluginBase.PluginResult(self._generate_text_output(result_dicts, command),
                                       self._generate_xml_output(result_dicts, command))


# == INTERNAL FUNCTIONS ==

# FORMATTING FUNCTIONS
    def _generate_text_output(self, result_dict_list, ssl_version):

        ACCEPTED_CIPHER_LINE_FORMAT = u'        {cipher_name:<50}{dh_size:<15}{key_size:<10}    {message:<60}'.format
        REJECTED_CIPHER_LINE_FORMAT = u'        {cipher_name:<50}    {message:<60}'.format
        CIPHER_LIST_TITLE_FORMAT = u'      {section_title:<32} '.format

        final_output_txt = [self.PLUGIN_TITLE_FORMAT(ssl_version.upper() + ' Cipher Suites')]


        # Not using a dict here as we want to sort the sections in the output
        dict_title_list = [('preferredCipherSuite', 'Preferred:'),
                       ('acceptedCipherSuites', 'Accepted:'),
                       ('errors', 'Undefined - An unexpected error happened:')]
        # TODO: fix this
#        if not self._shared_settings['hide_rejected_ciphers']:
#            dict_title_list.append(('rejectedCipherSuites', 'Rejected:'))

        for result_key, result_title in dict_title_list:

            # Sort the cipher suites by results
            result_list = sorted(result_dict_list[result_key].iteritems(), key=lambda (k,v): (v, k), reverse=True)

            # Add a new line and title
            if len(result_dict_list[result_key]) == 0:  # No ciphers
                pass  # Hide empty results
            else:
                final_output_txt.append(CIPHER_LIST_TITLE_FORMAT(section_title=result_title))

                # Add one line for each ciphers
                for (cipher_name, (msg, keysize, dh_infos)) in result_list:

                    # Replace the OpenSSL name with the RFC name if we have it
                    cipher_name = self.OPENSSL_TO_RFC_NAMES_MAPPING[ssl_version].get(cipher_name, cipher_name)

                    if keysize:
                        # Cipher suite was accepted
                        keysize_str = str(keysize) + ' bits'
                        if 'anon' in cipher_name:
                            # Always display ANON as the key size for anonymous ciphers to make it visible
                            keysize_str = 'ANONYMOUS'

                        dh_txt = "{}-{} bits".format(dh_infos["Type"], dh_infos["GroupSize"]) if dh_infos else '-'

                        cipher_line_txt = ACCEPTED_CIPHER_LINE_FORMAT(cipher_name=cipher_name, dh_size=dh_txt,
                                                                      key_size=keysize_str, message=msg)
                    else:
                        # Cipher suite was rejected
                        cipher_line_txt = REJECTED_CIPHER_LINE_FORMAT(cipher_name=cipher_name, message=msg)

                    final_output_txt.append(cipher_line_txt)

        if len(final_output_txt) == 1:
            # Server rejected all cipher suites
            final_output_txt.append('      Server rejected all cipher suites.')

        return final_output_txt


    @classmethod
    def _generate_xml_output(cls, result_dicts, command):

        xmlNodeList = []
        isProtocolSupported = False

        for (resultKey, resultDict) in result_dicts.items():
            xmlNode = Element(resultKey)

            # Sort the cipher suites by name to make the XML diff-able
            resultList = sorted(resultDict.items(), key=lambda (k,v): (k,v), reverse=False)

            # Add one element for each ciphers
            for (sslCipher, (msg, keysize, dh_infos)) in resultList:
                # Msg contains the server's HTTP status response, which could have unicode characters
                msg=msg.decode("utf-8")

                # Replace the OpenSSL name with the RFC name if we have it
                sslCipher = cls.OPENSSL_TO_RFC_NAMES_MAPPING[command].get(sslCipher, sslCipher)

                # The protocol is supported if at least one cipher suite was successfully negotiated
                if resultKey == 'acceptedCipherSuites':
                    isProtocolSupported = True

                cipherXmlAttr = {'name': sslCipher, 'connectionStatus': msg}
                if keysize:
                    cipherXmlAttr['keySize'] = str(keysize)

                # Add an Anonymous attribute for anonymous ciphers
                cipherXmlAttr['anonymous'] = str(True) if 'anon' in sslCipher else str(False)

                cipherXml = Element('cipherSuite', attrib = cipherXmlAttr)
                if dh_infos : 
                    cipherXml.append(Element('keyExchange', attrib=dh_infos))


                xmlNode.append(cipherXml)

            xmlNodeList.append(xmlNode)

        # Create the final node and specify if the protocol was supported
        xmlOutput = Element(command, title='{0} Cipher Suites'.format(command.upper()),
                            isProtocolSupported=str(isProtocolSupported))
        for xmlNode in xmlNodeList:
            xmlOutput.append(xmlNode)

        return xmlOutput


# SSL FUNCTIONS
    def _test_ciphersuite(self, server_connectivity_info, ssl_version, ssl_cipher):
        """
        Initiates a SSL handshake with the server, using the SSL version and
        cipher suite specified.
        """
        sslConn = server_connectivity_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version)
        sslConn.set_cipher_list(ssl_cipher)

        try: # Perform the SSL handshake
            sslConn.connect()

        except SSLHandshakeRejected as e:
            return 'rejectedCipherSuites', ssl_cipher, None, None, str(e)

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
            return 'acceptedCipherSuites', ssl_cipher, keysize, dh_infos, status_msg

        finally:
            sslConn.close()


    def _pref_ciphersuite(self, server_connectivity_info, ssl_version):
        """
        Initiates a SSL handshake with the server, using the SSL version and cipher
        suite specified.
        """

        sslConn = server_connectivity_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version)

        try: # Perform the SSL handshake
            sslConn.connect()

            ssl_cipher = sslConn.get_current_cipher_name()
            keysize = sslConn.get_current_cipher_bits()

            if 'ECDH' in ssl_cipher :
                dh_infos = sslConn.get_ecdh_param()
            elif 'DH' in ssl_cipher :
                dh_infos = sslConn.get_dh_param()
            else :
                dh_infos = None

            status_msg = sslConn.post_handshake_check()
            return 'preferredCipherSuite', ssl_cipher, keysize,  dh_infos, status_msg

        except:
            return None

        finally:
            sslConn.close()


    # Cipher suite name mappings so we can return the RFC names, instead of the OpenSSL names
    # Based on https://testssl.sh/openssl-rfc.mappping.html
    SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING = {
        "RC4-MD5": "SSL_CK_RC4_128_WITH_MD5",
        "EXP-RC4-MD5": "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
        "RC2-CBC-MD5": "SSL_CK_RC2_128_CBC_WITH_MD5",
        "EXP-RC2-CBC-MD5": "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
        "IDEA-CBC-MD5": "SSL_CK_IDEA_128_CBC_WITH_MD5",
        "DES-CBC-MD5": "SSL_CK_DES_64_CBC_WITH_MD5",
        "DES-CBC3-MD5": "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
        "RC4-64-MD5": "SSL_CK_RC4_64_WITH_MD5"
    }

    TLS_OPENSSL_TO_RFC_NAMES_MAPPING = {
        "NULL-MD5": "TLS_RSA_WITH_NULL_MD5",
        "NULL-SHA": "TLS_RSA_WITH_NULL_SHA",
        "EXP-RC4-MD5": "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        "RC4-MD5": "TLS_RSA_WITH_RC4_128_MD5",
        "RC4-SHA": "TLS_RSA_WITH_RC4_128_SHA",
        "EXP-RC2-CBC-MD5": "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        "IDEA-CBC-SHA": "TLS_RSA_WITH_IDEA_CBC_SHA",
        "EXP-DES-CBC-SHA": "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "DES-CBC-SHA": "TLS_RSA_WITH_DES_CBC_SHA",
        "DES-CBC3-SHA": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "EXP-DH-DSS-DES-CBC-SHA": "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "DH-DSS-DES-CBC-SHA": "TLS_DH_DSS_WITH_DES_CBC_SHA",
        "DH-DSS-DES-CBC3-SHA": "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
        "EXP-DH-RSA-DES-CBC-SHA": "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "DH-RSA-DES-CBC-SHA": "TLS_DH_RSA_WITH_DES_CBC_SHA",
        "DH-RSA-DES-CBC3-SHA": "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
        "EXP-EDH-DSS-DES-CBC-SHA": "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "EDH-DSS-DES-CBC-SHA": "TLS_DHE_DSS_WITH_DES_CBC_SHA",
        "EDH-DSS-DES-CBC3-SHA": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        "EXP-EDH-RSA-DES-CBC-SHA": "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "EDH-RSA-DES-CBC-SHA": "TLS_DHE_RSA_WITH_DES_CBC_SHA",
        "EDH-RSA-DES-CBC3-SHA": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "EXP-ADH-RC4-MD5": "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
        "ADH-RC4-MD5": "TLS_DH_anon_WITH_RC4_128_MD5",
        "EXP-ADH-DES-CBC-SHA": "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
        "ADH-DES-CBC-SHA": "TLS_DH_anon_WITH_DES_CBC_SHA",
        "ADH-DES-CBC3-SHA": "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
        "KRB5-DES-CBC-SHA": "TLS_KRB5_WITH_DES_CBC_SHA",
        "KRB5-DES-CBC3-SHA": "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
        "KRB5-RC4-SHA": "TLS_KRB5_WITH_RC4_128_SHA",
        "KRB5-IDEA-CBC-SHA": "TLS_KRB5_WITH_IDEA_CBC_SHA",
        "KRB5-DES-CBC-MD5": "TLS_KRB5_WITH_DES_CBC_MD5",
        "KRB5-DES-CBC3-MD5": "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
        "KRB5-RC4-MD5": "TLS_KRB5_WITH_RC4_128_MD5",
        "KRB5-IDEA-CBC-MD5": "TLS_KRB5_WITH_IDEA_CBC_MD5",
        "EXP-KRB5-DES-CBC-SHA": "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
        "EXP-KRB5-RC2-CBC-SHA": "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
        "EXP-KRB5-RC4-SHA": "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
        "EXP-KRB5-DES-CBC-MD5": "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
        "EXP-KRB5-RC2-CBC-MD5": "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
        "EXP-KRB5-RC4-MD5": "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
        "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "DH-DSS-AES128-SHA": "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
        "DH-RSA-AES128-SHA": "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
        "DHE-DSS-AES128-SHA": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "DHE-RSA-AES128-SHA": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "ADH-AES128-SHA": "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
        "DH-DSS-AES256-SHA": "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
        "DH-RSA-AES256-SHA": "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
        "DHE-DSS-AES256-SHA": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "DHE-RSA-AES256-SHA": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "ADH-AES256-SHA": "TLS_DH_anon_WITH_AES_256_CBC_SHA",
        "NULL-SHA256": "TLS_RSA_WITH_NULL_SHA256",
        "AES128-SHA256": "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "AES256-SHA256": "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "DH-DSS-AES128-SHA256": "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
        "DH-RSA-AES128-SHA256": "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
        "DHE-DSS-AES128-SHA256": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "CAMELLIA128-SHA": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "DH-DSS-CAMELLIA128-SHA": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
        "DH-RSA-CAMELLIA128-SHA": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "DHE-DSS-CAMELLIA128-SHA": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
        "DHE-RSA-CAMELLIA128-SHA": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "ADH-CAMELLIA128-SHA": "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
        "EXP1024-DES-CBC-SHA": "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
        "EXP1024-DHE-DSS-DES-CBC-SHA": "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
        "EXP1024-RC4-SHA": "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
        "EXP1024-DHE-DSS-RC4-SHA": "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
        "DHE-DSS-RC4-SHA": "TLS_DHE_DSS_WITH_RC4_128_SHA",
        "DHE-RSA-AES128-SHA256": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "DH-DSS-AES256-SHA256": "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
        "DH-RSA-AES256-SHA256": "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
        "DHE-DSS-AES256-SHA256": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        "DHE-RSA-AES256-SHA256": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "ADH-AES128-SHA256": "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
        "ADH-AES256-SHA256": "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
        "GOST94-GOST89-GOST89": "TLS_GOSTR341094_WITH_28147_CNT_IMIT",
        "GOST2001-GOST89-GOST89": "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
        "CAMELLIA256-SHA": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "DH-DSS-CAMELLIA256-SHA": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
        "DH-RSA-CAMELLIA256-SHA": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "DHE-DSS-CAMELLIA256-SHA": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
        "DHE-RSA-CAMELLIA256-SHA": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "ADH-CAMELLIA256-SHA": "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
        "PSK-RC4-SHA": "TLS_PSK_WITH_RC4_128_SHA",
        "PSK-3DES-EDE-CBC-SHA": "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
        "PSK-AES128-CBC-SHA": "TLS_PSK_WITH_AES_128_CBC_SHA",
        "PSK-AES256-CBC-SHA": "TLS_PSK_WITH_AES_256_CBC_SHA",
        "SEED-SHA": "TLS_RSA_WITH_SEED_CBC_SHA",
        "DH-DSS-SEED-SHA": "TLS_DH_DSS_WITH_SEED_CBC_SHA",
        "DH-RSA-SEED-SHA": "TLS_DH_RSA_WITH_SEED_CBC_SHA",
        "DHE-DSS-SEED-SHA": "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
        "DHE-RSA-SEED-SHA": "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        "ADH-SEED-SHA": "TLS_DH_anon_WITH_SEED_CBC_SHA",
        "AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "DHE-RSA-AES128-GCM-SHA256": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "DHE-RSA-AES256-GCM-SHA384": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "DH-RSA-AES128-GCM-SHA256": "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
        "DH-RSA-AES256-GCM-SHA384": "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
        "DHE-DSS-AES128-GCM-SHA256": "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        "DHE-DSS-AES256-GCM-SHA384": "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        "DH-DSS-AES128-GCM-SHA256": "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
        "DH-DSS-AES256-GCM-SHA384": "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
        "ADH-AES128-GCM-SHA256": "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
        "ADH-AES256-GCM-SHA384": "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
        "TLS_FALLBACK_SCSV": "TLS_FALLBACK_SCSV",
        "ECDH-ECDSA-NULL-SHA": "TLS_ECDH_ECDSA_WITH_NULL_SHA",
        "ECDH-ECDSA-RC4-SHA": "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
        "ECDH-ECDSA-DES-CBC3-SHA": "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "ECDH-ECDSA-AES128-SHA": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        "ECDH-ECDSA-AES256-SHA": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
        "ECDHE-ECDSA-NULL-SHA": "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
        "ECDHE-ECDSA-RC4-SHA": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        "ECDHE-ECDSA-DES-CBC3-SHA": "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "ECDH-RSA-NULL-SHA": "TLS_ECDH_RSA_WITH_NULL_SHA",
        "ECDH-RSA-RC4-SHA": "TLS_ECDH_RSA_WITH_RC4_128_SHA",
        "ECDH-RSA-DES-CBC3-SHA": "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
        "ECDH-RSA-AES128-SHA": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        "ECDH-RSA-AES256-SHA": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
        "ECDHE-RSA-NULL-SHA": "TLS_ECDHE_RSA_WITH_NULL_SHA",
        "ECDHE-RSA-RC4-SHA": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        "ECDHE-RSA-DES-CBC3-SHA": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "ECDHE-RSA-AES128-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "ECDHE-RSA-AES256-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "AECDH-NULL-SHA": "TLS_ECDH_anon_WITH_NULL_SHA",
        "AECDH-RC4-SHA": "TLS_ECDH_anon_WITH_RC4_128_SHA",
        "AECDH-DES-CBC3-SHA": "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
        "AECDH-AES128-SHA": "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        "AECDH-AES256-SHA": "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
        "SRP-3DES-EDE-CBC-SHA": "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
        "SRP-RSA-3DES-EDE-CBC-SHA": "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
        "SRP-DSS-3DES-EDE-CBC-SHA": "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
        "SRP-AES-128-CBC-SHA": "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
        "SRP-RSA-AES-128-CBC-SHA": "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
        "SRP-DSS-AES-128-CBC-SHA": "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
        "SRP-AES-256-CBC-SHA": "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
        "SRP-RSA-AES-256-CBC-SHA": "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
        "SRP-DSS-AES-256-CBC-SHA": "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
        "ECDHE-ECDSA-AES128-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "ECDHE-ECDSA-AES256-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "ECDH-ECDSA-AES128-SHA256": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
        "ECDH-ECDSA-AES256-SHA384": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
        "ECDHE-RSA-AES128-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "ECDHE-RSA-AES256-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "ECDH-RSA-AES128-SHA256": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
        "ECDH-RSA-AES256-SHA384": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "ECDH-ECDSA-AES128-GCM-SHA256": "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
        "ECDH-ECDSA-AES256-GCM-SHA384": "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "ECDH-RSA-AES128-GCM-SHA256": "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
        "ECDH-RSA-AES256-GCM-SHA384": "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
        "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "DHE-RSA-CHACHA20-POLY1305": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    }

    OPENSSL_TO_RFC_NAMES_MAPPING = {
        'sslv2': SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING,
        'sslv3': TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
        'tlsv1': TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
        'tlsv1_1': TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
        'tlsv1_2': TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    }
