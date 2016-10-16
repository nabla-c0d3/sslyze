# -*- coding: utf-8 -*-
"""Plugin to test the server server for supported OpenSSL cipher suites.
"""

from operator import attrgetter
from xml.etree.ElementTree import Element

from nassl import SSLV2, SSLV3, TLSV1, TLSV1_1, TLSV1_2
from nassl.ssl_client import SslClient

from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginResult
from sslyze.utils.ssl_connection import SSLHandshakeRejected, SSLConnection
from sslyze.utils.thread_pool import ThreadPool


class OpenSslCipherSuitesPlugin(plugin_base.PluginBase):

    interface = plugin_base.PluginInterface(
        "OpenSslCipherSuitesPlugin",
        "Scans the server(s) for supported OpenSSL cipher suites."
    )
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
        help="Option - Hides the (usually long) list of cipher suites that were rejected by the server(s)."
    )

    MAX_THREADS = 15
    SSL_VERSIONS_MAPPING = {'sslv2': SSLV2, 'sslv3': SSLV3, 'tlsv1': TLSV1, 'tlsv1_1': TLSV1_1, 'tlsv1_2': TLSV1_2}

    def process_task(self, server_connectivity_info, plugin_command, options_dict=None):
        ssl_version = self.SSL_VERSIONS_MAPPING[plugin_command]

        # Get the list of available cipher suites for the given ssl version
        ssl_client = SslClient(ssl_version=ssl_version)
        ssl_client.set_cipher_list('ALL:COMPLEMENTOFALL')
        cipher_list = ssl_client.get_cipher_list()

        # Scan for every available cipher suite
        thread_pool = ThreadPool()
        for cipher in cipher_list:
            thread_pool.add_job((self._test_ciphersuite, (server_connectivity_info, ssl_version, cipher)))

        # Scan for the preferred cipher suite
        preferred_cipher = self._get_preferred_ciphersuite(server_connectivity_info, ssl_version)

        # Start processing the jobs; One thread per cipher
        thread_pool.start(nb_threads=min(len(cipher_list), self.MAX_THREADS))

        accepted_cipher_list = []
        rejected_cipher_list = []
        errored_cipher_list = []

        # Store the results as they come
        for completed_job in thread_pool.get_result():
            (job, cipher_result) = completed_job
            if isinstance(cipher_result, AcceptedCipherSuite):
                accepted_cipher_list.append(cipher_result)
            elif isinstance(cipher_result, RejectedCipherSuite):
                rejected_cipher_list.append(cipher_result)
            elif isinstance(cipher_result, ErroredCipherSuite):
                errored_cipher_list.append(cipher_result)
            else:
                raise ValueError('Unexpected result')

        # Store thread pool errors; only something completely unexpected would trigger an error
        for failed_job in thread_pool.get_error():
            (_, exception) = failed_job
            raise exception

        thread_pool.join()

        plugin_result = OpenSSLCipherSuitesResult(server_connectivity_info, plugin_command, options_dict,
                                                  preferred_cipher, accepted_cipher_list, rejected_cipher_list,
                                                  errored_cipher_list)
        return plugin_result


    def _test_ciphersuite(self, server_connectivity_info, ssl_version, ssl_cipher):
        """Initiates a SSL handshake with the server, using the SSL version and cipher suite specified.
        """
        rfc_cipher_name = OPENSSL_TO_RFC_NAMES_MAPPING[ssl_version].get(ssl_cipher, ssl_cipher)
        ssl_connection = server_connectivity_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version)
        ssl_connection.set_cipher_list(ssl_cipher)

        try:
            # Perform the SSL handshake
            ssl_connection.connect()

        except SSLHandshakeRejected as e:
            cipher_result = RejectedCipherSuite(rfc_cipher_name, str(e))

        except Exception as e:
            cipher_result = ErroredCipherSuite(rfc_cipher_name, e)

        else:
            keysize = ssl_connection.get_current_cipher_bits()
                
            if 'ECDH' in ssl_cipher :
                dh_infos = ssl_connection.get_ecdh_param()
            elif 'DH' in ssl_cipher :
                dh_infos = ssl_connection.get_dh_param()
            else :
                dh_infos = None

            status_msg = ssl_connection.post_handshake_check()
            cipher_result = AcceptedCipherSuite(rfc_cipher_name, keysize, dh_infos, status_msg)

        finally:
            ssl_connection.close()

        return cipher_result


    def _get_preferred_ciphersuite(self, server_connectivity_info, ssl_version):
        """Initiates a SSL handshake with the server, using the SSL version and cipher suite specified.
        """
        preferred_cipher = None
        # First try the default cipher list, and then all ciphers
        for cipher_list in [SSLConnection.DEFAULT_SSL_CIPHER_LIST, 'ALL:COMPLEMENTOFALL']:
            ssl_connection = server_connectivity_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version)
            ssl_connection.set_cipher_list(cipher_list)
            try:
                # Perform the SSL handshake
                ssl_connection.connect()
                cipher_name = ssl_connection.get_current_cipher_name()
                rfc_cipher_name = OPENSSL_TO_RFC_NAMES_MAPPING[ssl_version].get(cipher_name, cipher_name)
                keysize = ssl_connection.get_current_cipher_bits()

                if 'ECDH' in cipher_name:
                    dh_infos = ssl_connection.get_ecdh_param()
                elif 'DH' in cipher_name:
                    dh_infos = ssl_connection.get_dh_param()
                else :
                    dh_infos = None

                status_msg = ssl_connection.post_handshake_check()
                preferred_cipher = AcceptedCipherSuite(rfc_cipher_name, keysize, dh_infos, status_msg)
                break

            except:
                pass

            finally:
                ssl_connection.close()

        return preferred_cipher


class AcceptedCipherSuite(object):
    def __init__(self, name, key_size, dh_info=None, post_handshake_response=None):
        self.name = name
        self.is_anonymous = True if 'anon' in name else False
        self.key_size = key_size
        self.dh_info = dh_info
        # The server's response after completing the handshake
        self.post_handshake_response = post_handshake_response.decode("utf-8")


class RejectedCipherSuite(object):
    def __init__(self, name, handshake_error_message):
        self.name = name
        self.is_anonymous = True if 'anon' in name else False
        self.handshake_error_message = handshake_error_message


class ErroredCipherSuite(object):
    def __init__(self, name, exception):
        self.name = name
        self.is_anonymous = True if 'anon' in name else False
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = '{} - {}'.format(str(exception.__class__.__name__), str(exception))


class OpenSSLCipherSuitesResult(PluginResult):
    """The result of running --sslv2, --sslv3, --tlsv1, --tlsv1_1 or --tlsv1_2 on a specific server.

    Attributes:
        accepted_cipher_list (List[AcceptedCipherSuite]): The list of cipher suites supported by the server.
        rejected_cipher_list (List[RejectedCipherSuite]): The list of cipher suites rejected by the server.
        errored_cipher_list (List[ErroredCipherSuite]): The list of cipher suites that triggered an unexpected error
            during the TLS handshake.
    """

    def __init__(self, server_info, plugin_command, plugin_options, preferred_cipher, accepted_cipher_list,
                 rejected_cipher_list, errored_cipher_list):
        super(OpenSSLCipherSuitesResult, self).__init__(server_info, plugin_command, plugin_options)

        self.preferred_cipher = preferred_cipher

        # Sort all the lists
        self.accepted_cipher_list = accepted_cipher_list
        self.accepted_cipher_list.sort(key=attrgetter('key_size'), reverse=True)

        self.rejected_cipher_list = rejected_cipher_list
        self.rejected_cipher_list.sort(key=attrgetter('name'), reverse=True)

        self.errored_cipher_list = errored_cipher_list
        self.errored_cipher_list.sort(key=attrgetter('name'), reverse=True)


    def as_xml(self):
        ssl_version = self.plugin_command
        is_protocol_supported = True if len(self.accepted_cipher_list) > 0 else False
        result_xml = Element(ssl_version, title='{0} Cipher Suites'.format(ssl_version.upper()),
                            isProtocolSupported=str(is_protocol_supported))

        # Output the preferred cipher
        preferred_xml = Element('preferredCipherSuite')
        if self.preferred_cipher:
            preferred_xml.append(self._format_accepted_cipher_xml(self.preferred_cipher))
        result_xml.append(preferred_xml)

        # Output all the accepted ciphers if any
        accepted_xml = Element('acceptedCipherSuites')
        if len(self.accepted_cipher_list) > 0:
            for cipher in self.accepted_cipher_list:
                accepted_xml.append(self._format_accepted_cipher_xml(cipher))
        result_xml.append(accepted_xml)

        # Output all the rejected ciphers if any
        rejected_xml = Element('rejectedCipherSuites')
        if len(self.rejected_cipher_list) > 0:
            for cipher in self.rejected_cipher_list:
                cipher_xml = Element('cipherSuite',
                                     attrib={'name': cipher.name,
                                             'anonymous': str(cipher.is_anonymous),
                                             'connectionStatus': cipher.handshake_error_message})
                rejected_xml.append(cipher_xml)
        result_xml.append(rejected_xml)

        # Output all the errored ciphers if any
        error_xml = Element('errors')
        if len(self.errored_cipher_list) > 0:
            for cipher in self.errored_cipher_list:
                cipher_xml = Element('cipherSuite',
                                     attrib={'name': cipher.name,
                                             'anonymous': str(cipher.is_anonymous),
                                             'connectionStatus': cipher.error_message})
                error_xml.append(cipher_xml)
        result_xml.append(error_xml)

        return result_xml


    def _format_accepted_cipher_xml(self, cipher):
        """Returns an XML node of an AcceptedCipherSuite's information.
        """
        cipher_xml = Element('cipherSuite',
                             attrib={'name': cipher.name,
                                     'connectionStatus': cipher.post_handshake_response,
                                     'keySize': str(cipher.key_size),
                                     'anonymous': str(cipher.is_anonymous)})
        if cipher.dh_info :
            cipher_xml.append(Element('keyExchange', attrib=cipher.dh_info))

        return cipher_xml


    ACCEPTED_CIPHER_LINE_FORMAT = u'        {cipher_name:<50}{dh_size:<15}{key_size:<10}    {status:<60}'.format
    REJECTED_CIPHER_LINE_FORMAT = u'        {cipher_name:<50}{error_message:<60}'.format
    CIPHER_LIST_TITLE_FORMAT = '      {section_title:<32} '.format
    VERSION_TITLE_FORMAT = '{ssl_version} Cipher Suites'.format

    def as_text(self):
        ssl_version = self.plugin_command
        hide_rejected_ciphers = self.plugin_options and self.plugin_options.get('hide_rejected_ciphers', False)
        result_txt = [self.PLUGIN_TITLE_FORMAT(self.VERSION_TITLE_FORMAT(ssl_version=ssl_version.upper()))]

        # Output the preferred cipher
        if self.preferred_cipher:
            result_txt.append(self.CIPHER_LIST_TITLE_FORMAT(section_title='Preferred:'))
            result_txt.append(self._format_accepted_cipher_txt(self.preferred_cipher))

        # Output all the accepted ciphers if any
        if len(self.accepted_cipher_list) > 0:
            result_txt.append(self.CIPHER_LIST_TITLE_FORMAT(section_title='Accepted:'))
            for cipher in self.accepted_cipher_list:
                result_txt.append(self._format_accepted_cipher_txt(cipher))
        elif hide_rejected_ciphers:
            result_txt.append('      Server rejected all cipher suites.')

        # Output all errors if any
        if len(self.errored_cipher_list) > 0:
            result_txt.append(self.CIPHER_LIST_TITLE_FORMAT(section_title='Undefined - An unexpected error happened:'))
            for cipher in self.errored_cipher_list:
                cipher_line_txt = self.REJECTED_CIPHER_LINE_FORMAT(cipher_name=cipher.name,
                                                                   error_message=cipher.error_message)
                result_txt.append(cipher_line_txt)

        # Output all rejected ciphers if needed
        if len(self.rejected_cipher_list) > 0 and not hide_rejected_ciphers:
            result_txt.append(self.CIPHER_LIST_TITLE_FORMAT(section_title='Rejected:'))
            for cipher in self.rejected_cipher_list:
                cipher_line_txt = self.REJECTED_CIPHER_LINE_FORMAT(cipher_name=cipher.name,
                                                                   error_message=cipher.handshake_error_message)
                result_txt.append(cipher_line_txt)

        return result_txt


    def _format_accepted_cipher_txt(self, cipher):
        """Returns a line of text with all of an AcceptedCipherSuite's information.
        """
        keysize_str = '{} bits'.format(cipher.key_size)
        if cipher.is_anonymous:
            # Always display ANON as the key size for anonymous ciphers to make it visible
            keysize_str = 'ANONYMOUS'

        dh_txt = "{}-{} bits".format(cipher.dh_info["Type"], cipher.dh_info["GroupSize"]) if cipher.dh_info else '-'
        cipher_line_txt = self.ACCEPTED_CIPHER_LINE_FORMAT(cipher_name=cipher.name, dh_size=dh_txt,
                                                           key_size=keysize_str, status=cipher.post_handshake_response)
        return cipher_line_txt


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
    "RC4-64-MD5": "SSL_CK_RC4_64_WITH_MD5",
    "NULL-MD5": "TLS_RSA_WITH_NULL_MD5",
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
    "EXP1024-RC4-MD5": "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
    "EXP1024-RC2-CBC-MD5": "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
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
    "RSA-PSK-RC4-SHA": "TLS_RSA_PSK_WITH_RC4_128_SHA",
    "RSA-PSK-3DES-EDE-CBC-SHA": "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
    "RSA-PSK-AES128-CBC-SHA": "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    "RSA-PSK-AES256-CBC-SHA": "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
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
    "CAMELLIA128-SHA256": "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "DH-DSS-CAMELLIA128-SHA256": "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    "DH-RSA-CAMELLIA128-SHA256": "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "DHE-DSS-CAMELLIA128-SHA256": "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    "DHE-RSA-CAMELLIA128-SHA256": "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ADH-CAMELLIA128-SHA256": "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
    "CAMELLIA256-SHA256": "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    "DH-DSS-CAMELLIA256-SHA256": "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    "DH-RSA-CAMELLIA256-SHA256": "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    "DHE-DSS-CAMELLIA256-SHA256": "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    "DHE-RSA-CAMELLIA256-SHA256": "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    "ADH-CAMELLIA256-SHA256": "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
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
    "ECDHE-ECDSA-CAMELLIA128-SHA256": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDHE-ECDSA-CAMELLIA256-SHA384": "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDH-ECDSA-CAMELLIA128-SHA256": "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDH-ECDSA-CAMELLIA256-SHA384": "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDHE-RSA-CAMELLIA128-SHA256": "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDHE-RSA-CAMELLIA256-SHA384": "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDH-RSA-CAMELLIA128-SHA256": "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    "ECDH-RSA-CAMELLIA256-SHA384": "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "DHE-RSA-CHACHA20-POLY1305": "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305-OLD": "OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305-OLD": "OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "DHE-RSA-CHACHA20-POLY1305-OLD": "OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

OPENSSL_TO_RFC_NAMES_MAPPING = {
    SSLV2: SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING,
    SSLV3: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    TLSV1: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    TLSV1_1: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    TLSV1_2: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
}
