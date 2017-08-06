# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import optparse
from abc import ABCMeta
from operator import attrgetter
from xml.etree.ElementTree import Element

from nassl.ssl_client import SslClient, OpenSslVersionEnum, ClientCertificateRequested
from sslyze.plugins.plugin_base import Plugin, PluginScanCommand
from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.utils.python_compatibility import IS_PYTHON_2
from sslyze.utils.ssl_connection import SSLConnection
from sslyze.utils.ssl_connection import SSLHandshakeRejected
from sslyze.utils.thread_pool import ThreadPool
from typing import Dict
from typing import List
from typing import Optional
from typing import Text


class CipherSuiteScanCommand(PluginScanCommand):

    __metaclass__ = ABCMeta

    def __init__(self, http_get=False, hide_rejected_ciphers=False):
        # type: (Optional[bool], Optional[bool]) -> None
        super(CipherSuiteScanCommand, self).__init__()
        # TODO(ad): Move these options to the CLI parser ?
        self.http_get = http_get
        self.hide_rejected_ciphers = hide_rejected_ciphers

    @classmethod
    def is_aggressive(cls):
        return True

    @classmethod
    def get_title(cls):
        return '{} Cipher Suites'.format(cls.get_cli_argument().upper())


class Sslv20ScanCommand(CipherSuiteScanCommand):
    """List the SSL 2.0 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls):
        return 'sslv2'

    @classmethod
    def is_aggressive(cls):
        # There only are few SSL 2 cipher suites to test for
        return False


class Sslv30ScanCommand(CipherSuiteScanCommand):
    """List the SSL 3.0 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls):
        return 'sslv3'


class Tlsv10ScanCommand(CipherSuiteScanCommand):
    """List the TLS 1.0 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls):
        return 'tlsv1'


class Tlsv11ScanCommand(CipherSuiteScanCommand):
    """List the TLS 1.1 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls):
        return 'tlsv1_1'


class Tlsv12ScanCommand(CipherSuiteScanCommand):
    """List the TLS 1.2 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls):
        return 'tlsv1_2'


class OpenSslCipherSuitesPlugin(Plugin):
    """Scan the server(s) for supported OpenSSL cipher suites.
    """

    MAX_THREADS = 15
    SSL_VERSIONS_MAPPING = {
        Sslv20ScanCommand: OpenSslVersionEnum.SSLV2,
        Sslv30ScanCommand: OpenSslVersionEnum.SSLV3,
        Tlsv10ScanCommand: OpenSslVersionEnum.TLSV1,
        Tlsv11ScanCommand: OpenSslVersionEnum.TLSV1_1,
        Tlsv12ScanCommand: OpenSslVersionEnum.TLSV1_2
    }

    @classmethod
    def get_available_commands(cls):
        return [Sslv20ScanCommand, Sslv30ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand]


    @classmethod
    def get_cli_option_group(cls):
        options = super(OpenSslCipherSuitesPlugin, cls).get_cli_option_group()

        # Add the special optional argument for this plugin's commands
        # They must match the names in the commands' contructor
        options.append(
            optparse.make_option(
                # TODO(ad): Move this option to the CLI parser ?
                '--http_get',
                help='Option - For each cipher suite, sends an HTTP GET request after completing the SSL handshake '
                     'and returns the HTTP status code.',
                action='store_true'
            )
        )
        options.append(
            optparse.make_option(
                # TODO(ad): Move this option to the CLI parser ?
                '--hide_rejected_ciphers',
                help='Option - Hides the (usually long) list of cipher suites that were rejected by the server(s).',
                action='store_true'
            )
        )
        return options


    def process_task(self, server_connectivity_info, scan_command):
        # type: (ServerConnectivityInfo, CipherSuiteScanCommand) -> CipherSuiteScanResult
        ssl_version = self.SSL_VERSIONS_MAPPING[scan_command.__class__]

        # Get the list of available cipher suites for the given ssl version
        ssl_client = SslClient(ssl_version=ssl_version)
        ssl_client.set_cipher_list('ALL:COMPLEMENTOFALL')
        cipher_list = ssl_client.get_cipher_list()

        # Scan for every available cipher suite
        thread_pool = ThreadPool()
        for cipher in cipher_list:
            thread_pool.add_job((self._test_cipher_suite, (server_connectivity_info, ssl_version, cipher)))

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

        # Test for the cipher suite preference
        preferred_cipher = self._get_preferred_cipher_suite(server_connectivity_info, ssl_version, accepted_cipher_list)

        # Generate the results
        plugin_result = CipherSuiteScanResult(server_connectivity_info, scan_command, preferred_cipher,
                                              accepted_cipher_list, rejected_cipher_list, errored_cipher_list)
        return plugin_result


    @staticmethod
    def _test_cipher_suite(server_connectivity_info, ssl_version, openssl_cipher_name):
        # type: (ServerConnectivityInfo, OpenSslVersionEnum, Text) -> CipherSuite
        """Initiates a SSL handshake with the server using the SSL version and the cipher suite specified.
        """
        ssl_connection = server_connectivity_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version)
        ssl_connection.ssl_client.set_cipher_list(openssl_cipher_name)
        if len(ssl_connection.ssl_client.get_cipher_list()) != 1:
            raise ValueError('Passed an OpenSSL string for multiple cipher suites: "{}"'.format(openssl_cipher_name))

        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            cipher_result = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)

        except SSLHandshakeRejected as e:
            cipher_result = RejectedCipherSuite(openssl_cipher_name, ssl_version, str(e))

        except ClientCertificateRequested:
            cipher_result = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)

        except Exception as e:
            cipher_result = ErroredCipherSuite(openssl_cipher_name, ssl_version, e)
            
        finally:
            ssl_connection.close()

        return cipher_result


    def _get_preferred_cipher_suite(self, server_connectivity_info, ssl_version, accepted_cipher_list):
        # type: (ServerConnectivityInfo, OpenSslVersionEnum, List[AcceptedCipherSuite]) -> Optional[AcceptedCipherSuite]
        """Try to detect the server's preferred cipher suite among all cipher suites supported by SSLyze.
        """
        if len(accepted_cipher_list) < 2:
            return None

        first_cipher_string = ', '.join([cipher.openssl_name for cipher in accepted_cipher_list])
        # Swap the first two ciphers in the list to see if the server always picks the client's first cipher
        second_cipher_string = ', '.join([accepted_cipher_list[1].openssl_name, accepted_cipher_list[0].openssl_name]
                                         + [cipher.openssl_name for cipher in accepted_cipher_list[2:]])

        first_cipher = self._get_selected_cipher_suite(server_connectivity_info, ssl_version, first_cipher_string)
        second_cipher = self._get_selected_cipher_suite(server_connectivity_info, ssl_version, second_cipher_string)

        if first_cipher.name == second_cipher.name:
            # The server has its own preference for picking a cipher suite
            return first_cipher
        else:
            # The server has no preferred cipher suite as it follows the client's preference for picking a cipher suite
            return None


    @staticmethod
    def _get_selected_cipher_suite(server_connectivity_info, ssl_version, openssl_cipher_string):
        # type: (ServerConnectivityInfo, OpenSslVersionEnum, Text) -> AcceptedCipherSuite
        """Given an OpenSSL cipher string (which may specify multiple cipher suites), return the cipher suite that was
        selected by the server during the SSL handshake.
        """
        ssl_connection = server_connectivity_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version)
        ssl_connection.ssl_client.set_cipher_list(openssl_cipher_string)

        # Perform the SSL handshake
        try:
            ssl_connection.connect()
            selected_cipher = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
        except ClientCertificateRequested:
            selected_cipher = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
        finally:
            ssl_connection.close()
        return selected_cipher


class CipherSuite(object):
    __metaclass__ = ABCMeta

    def __init__(self, openssl_name, ssl_version):
        # type: (Text, OpenSslVersionEnum) -> None
        self.openssl_name = openssl_name
        self.ssl_version = ssl_version
        self.is_anonymous = True if 'anon' in self.name else False

    @property
    def name(self):
        # type: () -> Text
        """OpenSSL uses a different naming convention than the corresponding RFCs.
        """
        return OPENSSL_TO_RFC_NAMES_MAPPING[self.ssl_version].get(self.openssl_name, self.openssl_name)


class AcceptedCipherSuite(CipherSuite):
    """An SSL cipher suite the server accepted.

    Attributes:
        name (Text): The cipher suite's RFC name.
        openssl_name (Text): The cipher suite's OpenSSL name.
        ssl_version (OpenSslVersionEnum): The cipher suite's corresponding SSL/TLS version.
        is_anonymous (bool): True if the cipher suite is an anonymous cipher suite (ie. no server authentication).
        key_size (int): The key size of the cipher suite's algorithm in bits.
        dh_info (Optional[Dict]): Additional details about the Diffie Helmann parameters for DH and ECDH cipher suites.
            None if the cipher suite is not DH or ECDH.
        post_handshake_response (Text): The server's response after completing the SSL/TLS handshake and sending a
            request, based on the TlsWrappedProtocolEnum set for this server. For example, this will contain an HTTP
            response when scanning an HTTPS server with TlsWrappedProtocolEnum.HTTPS as the tls_wrapped_protocol.
    """
    def __init__(self, openssl_name, ssl_version, key_size, dh_info=None, post_handshake_response=None):
        # type: (Text, OpenSslVersionEnum, int, Optional[Dict], Optional[Text]) -> None
        super(AcceptedCipherSuite, self).__init__(openssl_name, ssl_version)
        self.key_size = key_size
        self.dh_info = dh_info
        self.post_handshake_response = post_handshake_response
        if IS_PYTHON_2:
            self.post_handshake_response = post_handshake_response.decode('utf-8')

    @classmethod
    def from_ongoing_ssl_connection(cls, ssl_connection, ssl_version):
        # type: (SSLConnection, OpenSslVersionEnum) -> AcceptedCipherSuite
        keysize = ssl_connection.ssl_client.get_current_cipher_bits()
        picked_cipher_name = ssl_connection.ssl_client.get_current_cipher_name()
        if 'ECDH' in picked_cipher_name:
            dh_infos = ssl_connection.ssl_client.get_ecdh_param()
        elif 'DH' in picked_cipher_name:
            dh_infos = ssl_connection.ssl_client.get_dh_param()
        else:
            dh_infos = None

        status_msg = ssl_connection.post_handshake_check()
        return AcceptedCipherSuite(picked_cipher_name, ssl_version, keysize, dh_infos, status_msg)


class RejectedCipherSuite(CipherSuite):
    """An SSL cipher suite the server explicitly rejected.

    Attributes:
        name (Text): The cipher suite's RFC name.
        openssl_name (Text): The cipher suite's OpenSSL name.
        ssl_version (OpenSslVersionEnum): The cipher suite's corresponding SSL/TLS version.
        is_anonymous (bool): True if the cipher suite is an anonymous cipher suite (ie. no server authentication).
        handshake_error_message (Text): The SSL/TLS error returned by the server to close the handshake.
    """
    def __init__(self, openssl_name, ssl_version, handshake_error_message):
        # type: (Text, OpenSslVersionEnum, bytes) -> None
        super(RejectedCipherSuite, self).__init__(openssl_name, ssl_version)
        self.handshake_error_message = handshake_error_message


class ErroredCipherSuite(CipherSuite):
    """An SSL cipher suite that triggered an unexpected error during the SSL handshake with the server.

    Attributes:
        name (Text): The cipher suite's RFC name.
        openssl_name (Text): The cipher suite's OpenSSL name.
        ssl_version (OpenSslVersionEnum): The cipher suite's corresponding SSL/TLS version.
        is_anonymous (bool): True if the cipher suite is an anonymous cipher suite (ie. no server authentication).
        error_message (Text): The text-formatted exception that was raised during the handshake.
    """
    def __init__(self, openssl_name, ssl_version, exception):
        # type: (Text, OpenSslVersionEnum, Exception) -> None
        super(ErroredCipherSuite, self).__init__(openssl_name, ssl_version)
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = '{} - {}'.format(str(exception.__class__.__name__), str(exception))


class CipherSuiteScanResult(PluginScanResult):
    """The result of running a CipherSuiteScanCommand on a specific server.

    Attributes:
        accepted_cipher_list (List[AcceptedCipherSuite]): The list of cipher suites supported supported by both SSLyze
            and the server.
        rejected_cipher_list (List[RejectedCipherSuite]): The list of cipher suites supported by SSLyze that were
            rejected by the server.
        errored_cipher_list (List[ErroredCipherSuite]): The list of cipher suites supported by SSLyze that triggered an
            unexpected error during the TLS handshake with the server.
        preferred_cipher (AcceptedCipherSuite): The server's preferred cipher suite among all the cipher suites
            supported by SSLyze. None if the server follows the client's preference or if none of SSLyze's cipher suites
            are supported by the server.
    """

    def __init__(
            self,
            server_info,           # type: ServerConnectivityInfo
            scan_command,          # type: CipherSuiteScanCommand
            preferred_cipher,      # type: AcceptedCipherSuite
            accepted_cipher_list,  # type: List[AcceptedCipherSuite]
            rejected_cipher_list,  # type: List[RejectedCipherSuite]
            errored_cipher_list    # type: List[ErroredCipherSuite]
            ):
        # type: (...) -> None
        super(CipherSuiteScanResult, self).__init__(server_info, scan_command)

        self.preferred_cipher = preferred_cipher

        # Sort all the lists
        self.accepted_cipher_list = accepted_cipher_list
        self.accepted_cipher_list.sort(key=attrgetter('key_size'), reverse=True)

        self.rejected_cipher_list = rejected_cipher_list
        self.rejected_cipher_list.sort(key=attrgetter('name'), reverse=True)

        self.errored_cipher_list = errored_cipher_list
        self.errored_cipher_list.sort(key=attrgetter('name'), reverse=True)


    def as_xml(self):
        is_protocol_supported = True if len(self.accepted_cipher_list) > 0 else False
        result_xml = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title(),
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


    @staticmethod
    def _format_accepted_cipher_xml(cipher):
        """Returns an XML node of an AcceptedCipherSuite's information.
        """
        cipher_xml = Element('cipherSuite',
                             attrib={'name': cipher.name,
                                     'connectionStatus': cipher.post_handshake_response,
                                     'keySize': str(cipher.key_size),
                                     'anonymous': str(cipher.is_anonymous)})
        if cipher.dh_info:
            cipher_xml.append(Element('keyExchange', attrib=cipher.dh_info))

        return cipher_xml


    ACCEPTED_CIPHER_LINE_FORMAT = '        {cipher_name:<50}{dh_size:<15}{key_size:<10}    {status:<60}'
    REJECTED_CIPHER_LINE_FORMAT = '        {cipher_name:<50}{error_message:<60}'

    def as_text(self):
        result_txt = [self._format_title(self.scan_command.get_title())]

        # Output all the accepted ciphers if any
        if len(self.accepted_cipher_list) > 0:
            # Start with the preferred cipher
            result_txt.append(self._format_subtitle('Preferred:'))
            if self.preferred_cipher:
                result_txt.append(self._format_accepted_cipher_txt(self.preferred_cipher))
            else:
                result_txt.append(self.REJECTED_CIPHER_LINE_FORMAT.format(
                    cipher_name='None - Server followed client cipher suite preference.', error_message=''
                ))

            # Then display all ciphers that were accepted
            result_txt.append(self._format_subtitle('Accepted:'))
            for cipher in self.accepted_cipher_list:
                result_txt.append(self._format_accepted_cipher_txt(cipher))
        elif self.scan_command.hide_rejected_ciphers:
            result_txt.append('      Server rejected all cipher suites.')

        # Output all errors if any
        if len(self.errored_cipher_list) > 0:
            result_txt.append(self._format_subtitle('Undefined - An unexpected error happened:')
            )
            for cipher in self.errored_cipher_list:
                cipher_line_txt = self.REJECTED_CIPHER_LINE_FORMAT.format(cipher_name=cipher.name,
                                                                          error_message=cipher.error_message)
                result_txt.append(cipher_line_txt)

        # Output all rejected ciphers if needed
        if len(self.rejected_cipher_list) > 0 and not self.scan_command.hide_rejected_ciphers:
            result_txt.append(self._format_subtitle('Rejected:'))
            for cipher in self.rejected_cipher_list:
                cipher_line_txt = self.REJECTED_CIPHER_LINE_FORMAT.format(cipher_name=cipher.name,
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
        cipher_line_txt = self.ACCEPTED_CIPHER_LINE_FORMAT.format(cipher_name=cipher.name, dh_size=dh_txt,
                                                                  key_size=keysize_str,
                                                                  status=cipher.post_handshake_response)
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
    OpenSslVersionEnum.SSLV2: SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.SSLV3: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1_1: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1_2: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
}
