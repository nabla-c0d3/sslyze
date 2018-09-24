import optparse
from abc import ABC
from operator import attrgetter
from xml.etree.ElementTree import Element

from nassl.ssl_client import OpenSslVersionEnum, ClientCertificateRequested
from sslyze.plugins.plugin_base import Plugin, PluginScanCommand
from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SslConnection
from sslyze.utils.ssl_connection import SslHandshakeRejected
from sslyze.utils.thread_pool import ThreadPool
from typing import Dict, Type
from typing import List
from typing import Optional

from sslyze.utils.tls12_workaround import WorkaroundForTls12ForCipherSuites


class CouldNotDetermineCipherSuite(Exception):
    """No selected cipher suite could be determined from an ongoing TLS connection."""


class CipherSuiteScanCommand(PluginScanCommand, ABC):

    def __init__(self, http_get: bool = False, hide_rejected_ciphers: bool = False) -> None:
        super().__init__()
        # TODO(ad): Move these options to the CLI parser ?
        self.http_get = http_get
        self.hide_rejected_ciphers = hide_rejected_ciphers

    @classmethod
    def is_aggressive(cls) -> bool:
        return True

    @classmethod
    def get_title(cls) -> str:
        return '{} Cipher Suites'.format(cls.get_cli_argument().upper())


class Sslv20ScanCommand(CipherSuiteScanCommand):
    """List the SSL 2.0 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls) -> str:
        return 'sslv2'

    @classmethod
    def is_aggressive(cls) -> bool:
        # There only are few SSL 2 cipher suites to test for
        return False


class Sslv30ScanCommand(CipherSuiteScanCommand):
    """List the SSL 3.0 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls) -> str:
        return 'sslv3'


class Tlsv10ScanCommand(CipherSuiteScanCommand):
    """List the TLS 1.0 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls) -> str:
        return 'tlsv1'


class Tlsv11ScanCommand(CipherSuiteScanCommand):
    """List the TLS 1.1 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls) -> str:
        return 'tlsv1_1'


class Tlsv12ScanCommand(CipherSuiteScanCommand):
    """List the TLS 1.2 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls) -> str:
        return 'tlsv1_2'


class Tlsv13ScanCommand(CipherSuiteScanCommand):
    """List the TLS 1.3 OpenSSL cipher suites supported by the server(s).
    """
    @classmethod
    def get_cli_argument(cls) -> str:
        return 'tlsv1_3'


class OpenSslCipherSuitesPlugin(Plugin):
    """Scan the server(s) for supported OpenSSL cipher suites.
    """

    MAX_THREADS = 10
    SSL_VERSIONS_MAPPING: Dict[Type[CipherSuiteScanCommand], OpenSslVersionEnum] = {
        Sslv20ScanCommand: OpenSslVersionEnum.SSLV2,
        Sslv30ScanCommand: OpenSslVersionEnum.SSLV3,
        Tlsv10ScanCommand: OpenSslVersionEnum.TLSV1,
        Tlsv11ScanCommand: OpenSslVersionEnum.TLSV1_1,
        Tlsv12ScanCommand: OpenSslVersionEnum.TLSV1_2,
        Tlsv13ScanCommand: OpenSslVersionEnum.TLSV1_3,
    }

    @classmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        return list(cls.SSL_VERSIONS_MAPPING.keys())

    @classmethod
    def get_cli_option_group(cls) -> List[optparse.Option]:
        options = super().get_cli_option_group()

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

    def process_task(
            self,
            server_connectivity_info: ServerConnectivityInfo,
            scan_command: PluginScanCommand
    ) -> 'CipherSuiteScanResult':
        if not isinstance(scan_command, CipherSuiteScanCommand):
            raise ValueError('Unexpected scan command')

        ssl_version = self.SSL_VERSIONS_MAPPING[scan_command.__class__]
        # Get the list of available cipher suites for the given ssl version
        cipher_list: List[str] = []
        if ssl_version == OpenSslVersionEnum.TLSV1_2:
            # For TLS 1.2, we have to use both the legacy and modern OpenSSL to cover all cipher suites
            ssl_connection_legacy = server_connectivity_info.get_preconfigured_ssl_connection(
                override_ssl_version=ssl_version, should_use_legacy_openssl=True
            )
            ssl_connection_legacy.ssl_client.set_cipher_list('ALL:COMPLEMENTOFALL:-PSK:-SRP')
            cipher_list.extend(ssl_connection_legacy.ssl_client.get_cipher_list())

            ssl_connection_modern = server_connectivity_info.get_preconfigured_ssl_connection(
                override_ssl_version=ssl_version, should_use_legacy_openssl=False
            )
            # Disable the TLS 1.3 cipher suites with the new OpenSSL API
            ssl_connection_modern.ssl_client.set_ciphersuites('')
            # Enable all other cipher suites
            ssl_connection_modern.ssl_client.set_cipher_list('ALL:COMPLEMENTOFALL:-PSK:-SRP')
            cipher_list.extend(ssl_connection_modern.ssl_client.get_cipher_list())

            # And remove duplicates (ie. supported by both legacy and modern OpenSSL)
            cipher_list = list(set(cipher_list))
        elif ssl_version == OpenSslVersionEnum.TLSV1_3:
            # TLS 1.3 only has 5 cipher suites so we can hardcode them
            cipher_list = [
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_128_CCM_8_SHA256',
                'TLS_AES_128_CCM_SHA256',
            ]
        else:
            ssl_connection = server_connectivity_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version)
            # Disable SRP and PSK cipher suites as they need a special setup in the client and are never used
            ssl_connection.ssl_client.set_cipher_list('ALL:COMPLEMENTOFALL:-PSK:-SRP')
            # And remove TLS 1.3 cipher suites
            cipher_list = [cipher for cipher in ssl_connection.ssl_client.get_cipher_list() if 'TLS13' not in cipher]

        # Scan for every available cipher suite
        thread_pool = ThreadPool()
        for cipher in cipher_list:
            thread_pool.add_job((self._test_cipher_suite, [server_connectivity_info, ssl_version, cipher]))

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
        preferred_cipher = None
        server_ordered_ciphers = self._get_preferred_cipher_suite_order(
                server_connectivity_info, ssl_version, accepted_cipher_list)
        if server_ordered_ciphers:
            accepted_cipher_list = server_ordered_ciphers
            preferred_cipher = accepted_cipher_list[0]

        # Generate the results
        plugin_result = CipherSuiteScanResult(server_connectivity_info, scan_command, preferred_cipher,
                                              accepted_cipher_list, rejected_cipher_list, errored_cipher_list)
        return plugin_result

    @staticmethod
    def _test_cipher_suite(
            server_connectivity_info: ServerConnectivityInfo,
            ssl_version: OpenSslVersionEnum,
            openssl_cipher_name: str
    ) -> 'CipherSuite':
        """Initiates a SSL handshake with the server using the SSL version and the cipher suite specified.
        """
        requires_legacy_openssl = True
        if ssl_version == OpenSslVersionEnum.TLSV1_2:
            # For TLS 1.2, we need to pick the right version of OpenSSL depending on which cipher suite
            requires_legacy_openssl = WorkaroundForTls12ForCipherSuites.requires_legacy_openssl(openssl_cipher_name)
        elif ssl_version == OpenSslVersionEnum.TLSV1_3:
            requires_legacy_openssl = False

        ssl_connection = server_connectivity_info.get_preconfigured_ssl_connection(
            override_ssl_version=ssl_version,
            should_use_legacy_openssl=requires_legacy_openssl
        )

        # Only enable the cipher suite to test; not trivial anymore since OpenSSL 1.1.1 and TLS 1.3
        if ssl_version == OpenSslVersionEnum.TLSV1_3:
            # The function to control cipher suites is different for TLS 1.3
            # Disable the default, non-TLS 1.3 cipher suites
            ssl_connection.ssl_client.set_cipher_list('')
            # Enable the one TLS 1.3 cipher suite we want to test
            ssl_connection.ssl_client.set_ciphersuites(openssl_cipher_name)
        else:
            if not requires_legacy_openssl:
                # Disable the TLS 1.3 cipher suites if we are using the modern client
                ssl_connection.ssl_client.set_ciphersuites('')

            ssl_connection.ssl_client.set_cipher_list(openssl_cipher_name)

        if len(ssl_connection.ssl_client.get_cipher_list()) != 1:
            raise ValueError(f'Passed an OpenSSL string for multiple cipher suites: "{openssl_cipher_name}": '
                             f'{str(ssl_connection.ssl_client.get_cipher_list())}')

        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            cipher_result: CipherSuite = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)

        except SslHandshakeRejected as e:
            cipher_result = RejectedCipherSuite(openssl_cipher_name, ssl_version, str(e))

        except ClientCertificateRequested:
            # TODO(AD): Sometimes get_current_cipher_name() called in from_ongoing_ssl_connection() will return None
            # When the handshake failed due to ClientCertificateRequested
            # We need to rewrite this logic to not use OpenSSL for looking up key size and RFC names as it is
            # too complicated
            # cipher_result = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
            # The ClientCertificateRequested exception already proves that the cipher suite was accepted
            # Workaround here:
            cipher_result = AcceptedCipherSuite(openssl_cipher_name, ssl_version, None, None)

        except Exception as e:
            cipher_result = ErroredCipherSuite(openssl_cipher_name, ssl_version, e)

        finally:
            ssl_connection.close()

        return cipher_result

    @classmethod
    def _get_preferred_cipher_suite_order(
            cls,
            server_connectivity_info: ServerConnectivityInfo,
            ssl_version: OpenSslVersionEnum,
            accepted_cipher_list: List['AcceptedCipherSuite']
    ) -> Optional[List['AcceptedCipherSuite']]:
        """Try to detect the server's preferred cipher suite order among all cipher suites supported by SSLyze.

        The algorithm for determining the server's full preferred cipher suite
        order is as follows:

        1. Send the unordered list to the server.
        2. Move the accepted cipher to the ordered list.
        3. If the accepted cipher was the first one in the list, add it to
           the end of the cipher string and send again to verify server
           ordering is enabled.
        4. If the server did not give us the same cipher it chose last time:
               the server has no preference; stop and return `None`
           Else:
               remove the previously accepted cipher from the unordered list and continue
        5. Send the unordered list again, moving the accepted cipher from the
           unordered list to the ordered one. Repeat until the unordered list is empty.
        """
        if len(accepted_cipher_list) < 2:
            return None

        unordered_cipher_names = [cipher.openssl_name for cipher in accepted_cipher_list]
        server_ordered_cipher_list = []
        should_use_legacy_openssl = None

        # For TLS 1.2, we need to figure whether the modern or legacy OpenSSL should be used to connect
        if ssl_version == OpenSslVersionEnum.TLSV1_2:
            should_use_legacy_openssl = True
            # If there is at least one modern-supported cipher suite, use the modern OpenSSL client
            set_of_legacy_cipher_names = set(WorkaroundForTls12ForCipherSuites.get_legacy_ciphers())
            if set(unordered_cipher_names) - set_of_legacy_cipher_names:
                should_use_legacy_openssl = False

        cipher_str = ', '.join(unordered_cipher_names)
        try:
            # 1. Send the unordered list to the server.
            selected_cipher = cls._get_selected_cipher_suite(
                server_connectivity_info, ssl_version, cipher_str, should_use_legacy_openssl
            )

            # 2. Move the accepted cipher to the ordered list.
            server_ordered_cipher_list.append(selected_cipher)

            # 3. If the accepted cipher was the first one in the list, add it to
            #    the end of the cipher string and send again to verify server
            #    ordering is enabled.
            if selected_cipher.openssl_name == unordered_cipher_names[0]:
                unordered_cipher_names.append(unordered_cipher_names.pop(0))
                cipher_str = ', '.join(unordered_cipher_names)
                next_selected_cipher = cls._get_selected_cipher_suite(
                    server_connectivity_info, ssl_version, cipher_str, should_use_legacy_openssl
                )

                if next_selected_cipher.openssl_name != selected_cipher.openssl_name:
                    # The server has no preferred cipher suite order as it follows the
                    # client's preference for picking a cipher suite
                    return None

                # 4. The server does have its own preference for picking a cipher
                #    suite. Remove the previously accepted cipher from the unordered list and continue
                unordered_cipher_names.pop()
            else:
                # The server selected a cipher other than the first one offered
                # by the client. Remove the selected cipher from the unordered
                # list and continue.
                unordered_cipher_names.remove(selected_cipher.openssl_name)

        except (SslHandshakeRejected, ConnectionError):
            # Could not complete a handshake
            return None

        except CouldNotDetermineCipherSuite:
            # The handshake failed using the modern (OpenSSL 1.1.1+ based) SSL client
            # due to attempting to handshake with a server that requires
            # client-side certificates without providing one.
            #
            # In this case, we cannot reliably determine the server's
            # preference had a certificate been provided, so this method will
            # also return `None`, indicating no server cipher suite ordering
            # preference.
            return None

        # 5. Send the unordered list again, moving the accepted cipher from the
        #    unordered list to the ordered one. Repeat until the unordered list is empty.
        while unordered_cipher_names:
            # Re-evaluate use of the legacy SSL client on each iteration
            should_use_legacy_openssl = None
            if ssl_version == OpenSslVersionEnum.TLSV1_2:
                should_use_legacy_openssl = True
                if set(unordered_cipher_names) - set_of_legacy_cipher_names:
                    should_use_legacy_openssl = False
            cipher_str = ', '.join(unordered_cipher_names)
            try:
                selected_cipher = cls._get_selected_cipher_suite(
                    server_connectivity_info, ssl_version, cipher_str, should_use_legacy_openssl
                )
            except (SslHandshakeRejected, ConnectionError):
                return None
            server_ordered_cipher_list.append(selected_cipher)
            unordered_cipher_names.remove(selected_cipher.openssl_name)
        return server_ordered_cipher_list

    @staticmethod
    def _get_selected_cipher_suite(
            server_connectivity: ServerConnectivityInfo,
            ssl_version: OpenSslVersionEnum,
            openssl_cipher_str: str,
            should_use_legacy_openssl: Optional[bool]
    ) -> 'AcceptedCipherSuite':
        """Given an OpenSSL cipher string (which may specify multiple cipher suites), return the cipher suite that was
        selected by the server during the SSL handshake.

        Raises:
            CouldNotDetermineCipherSuite: if the selected cipher suite name could not be retrieved from the connection
        """
        ssl_connection = server_connectivity.get_preconfigured_ssl_connection(
            override_ssl_version=ssl_version, should_use_legacy_openssl=should_use_legacy_openssl
        )

        if ssl_version == OpenSslVersionEnum.TLSV1_3 and not should_use_legacy_openssl:
            ssl_connection.ssl_client.set_cipher_list('')
            ssl_connection.ssl_client.set_ciphersuites(openssl_cipher_str.replace(', ', ':'))
        else:
            ssl_connection.ssl_client.set_cipher_list(openssl_cipher_str)

        # Perform the SSL handshake
        try:
            ssl_connection.connect()
            selected_cipher = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
        except ClientCertificateRequested:
            selected_cipher = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)
        finally:
            ssl_connection.close()
        return selected_cipher


class CipherSuite(ABC):

    def __init__(self, openssl_name: str, ssl_version: OpenSslVersionEnum) -> None:
        if openssl_name is None:
            raise ValueError('Cannot create a CipherSuite without an openssl name!')
        self.openssl_name = openssl_name
        self.ssl_version = ssl_version
        self.is_anonymous = True if 'anon' in self.name else False

    @property
    def name(self) -> str:
        """OpenSSL uses a different naming convention than the corresponding RFCs.
        """
        return OPENSSL_TO_RFC_NAMES_MAPPING[self.ssl_version].get(self.openssl_name, self.openssl_name)


class AcceptedCipherSuite(CipherSuite):
    """An SSL cipher suite the server accepted.

    Attributes:
        name (str): The cipher suite's RFC name.
        openssl_name (str): The cipher suite's OpenSSL name.
        ssl_version (OpenSslVersionEnum): The cipher suite's corresponding SSL/TLS version.
        is_anonymous (bool): True if the cipher suite is an anonymous cipher suite (ie. no server authentication).
        key_size (Optional[int]): The key size of the cipher suite's algorithm in bits. None if the key size could not
            be looked up for this cipher suite.
        post_handshake_response (Optional[str]): The server's response after completing the SSL/TLS handshake and
            sending a request, based on the TlsWrappedProtocolEnum set for this server. For example, this will contain
            an HTTP response when scanning an HTTPS server with TlsWrappedProtocolEnum.HTTPS as the
            tls_wrapped_protocol.
    """
    def __init__(
            self,
            openssl_name: str,
            ssl_version: OpenSslVersionEnum,
            key_size: Optional[int],  # TODO(AD): Make it non-optional again by fixing client certificate handling
            post_handshake_response: Optional[str] = None,
    ) -> None:
        super().__init__(openssl_name, ssl_version)
        self.key_size = key_size
        self.post_handshake_response = post_handshake_response

    @classmethod
    def from_ongoing_ssl_connection(
            cls,
            ssl_connection: SslConnection,
            ssl_version: OpenSslVersionEnum
    ) -> 'AcceptedCipherSuite':
        """Determine the name of the currently selected cipher suite.

        Raises:
            CouldNotDetermineCipherSuite: if the name could not be retrieved from the connection
        """
        keysize = ssl_connection.ssl_client.get_current_cipher_bits()
        picked_cipher_name = ssl_connection.ssl_client.get_current_cipher_name()
        status_msg = ssl_connection.post_handshake_check()
        try:
            suite = AcceptedCipherSuite(picked_cipher_name, ssl_version, keysize, status_msg)
        except ValueError:
            raise CouldNotDetermineCipherSuite(
                f'Could not obtain cipher suite name from {ssl_version.name} connection!')
        return suite


class RejectedCipherSuite(CipherSuite):
    """An SSL cipher suite the server explicitly rejected.

    Attributes:
        name (str): The cipher suite's RFC name.
        openssl_name (str): The cipher suite's OpenSSL name.
        ssl_version (OpenSslVersionEnum): The cipher suite's corresponding SSL/TLS version.
        is_anonymous (bool): True if the cipher suite is an anonymous cipher suite (ie. no server authentication).
        handshake_error_message (str): The SSL/TLS error returned by the server to close the handshake.
    """
    def __init__(self, openssl_name: str, ssl_version: OpenSslVersionEnum, handshake_error_message: str) -> None:
        super().__init__(openssl_name, ssl_version)
        self.handshake_error_message = handshake_error_message


class ErroredCipherSuite(CipherSuite):
    """An SSL cipher suite that triggered an unexpected error during the SSL handshake with the server.

    Attributes:
        name (Text): The cipher suite's RFC name.
        openssl_name (str): The cipher suite's OpenSSL name.
        ssl_version (OpenSslVersionEnum): The cipher suite's corresponding SSL/TLS version.
        is_anonymous (bool): True if the cipher suite is an anonymous cipher suite (ie. no server authentication).
        error_message (str): The text-formatted exception that was raised during the handshake.
    """
    def __init__(self, openssl_name: str, ssl_version: OpenSslVersionEnum, exception: Exception) -> None:
        super().__init__(openssl_name, ssl_version)
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = '{} - {}'.format(str(exception.__class__.__name__), str(exception))


class CipherSuiteScanResult(PluginScanResult):
    """The result of running a CipherSuiteScanCommand on a specific server.

    Attributes:
        accepted_cipher_list (List[AcceptedCipherSuite]): The list of cipher suites supported supported by both SSLyze
            and the server, in server preference order, if applicable.
        rejected_cipher_list (List[RejectedCipherSuite]): The list of cipher suites supported by SSLyze that were
            rejected by the server.
        errored_cipher_list (List[ErroredCipherSuite]): The list of cipher suites supported by SSLyze that triggered an
            unexpected error during the TLS handshake with the server.
        preferred_cipher (Optional[AcceptedCipherSuite]): The server's preferred cipher suite among all the cipher
            suites supported by SSLyze. `None` if the server follows the client's preference or if none of SSLyze's
            cipher suites are supported by the server.
    """

    def __init__(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: CipherSuiteScanCommand,
            preferred_cipher: Optional[AcceptedCipherSuite],
            accepted_cipher_list: List[AcceptedCipherSuite],
            rejected_cipher_list: List[RejectedCipherSuite],
            errored_cipher_list: List[ErroredCipherSuite]
    ) -> None:
        super().__init__(server_info, scan_command)

        self.preferred_cipher = preferred_cipher

        # Do not sort the accepted cipher list by name if it is already
        # ordered in server preference; otherwise sort it like the others
        self.accepted_cipher_list = accepted_cipher_list
        if not preferred_cipher:
            self.accepted_cipher_list.sort(key=attrgetter('name'), reverse=True)

        # Sort the other lists
        self.rejected_cipher_list = rejected_cipher_list
        self.rejected_cipher_list.sort(key=attrgetter('name'), reverse=True)

        self.errored_cipher_list = errored_cipher_list
        self.errored_cipher_list.sort(key=attrgetter('name'), reverse=True)

    def as_xml(self) -> Element:
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
            for accepted_cipher in self.accepted_cipher_list:
                accepted_xml.append(self._format_accepted_cipher_xml(accepted_cipher))
        result_xml.append(accepted_xml)

        # Output all the rejected ciphers if any
        rejected_xml = Element('rejectedCipherSuites')
        if len(self.rejected_cipher_list) > 0:
            for rejected_cipher in self.rejected_cipher_list:
                cipher_xml = Element('cipherSuite',
                                     attrib={'name': rejected_cipher.name,
                                             'anonymous': str(rejected_cipher.is_anonymous),
                                             'connectionStatus': rejected_cipher.handshake_error_message})
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
    def _format_accepted_cipher_xml(cipher: AcceptedCipherSuite) -> Element:
        cipher_attributes = {
            'name': cipher.name,
            'keySize': str(cipher.key_size),
            'anonymous': str(cipher.is_anonymous)
        }
        if cipher.post_handshake_response is not None:
            cipher_attributes['connectionStatus'] = cipher.post_handshake_response

        cipher_xml = Element('cipherSuite', attrib=cipher_attributes)
        return cipher_xml

    ACCEPTED_CIPHER_LINE_FORMAT = '        {cipher_name:<50}{dh_size:<15}{key_size:<10}    {status:<60}'
    REJECTED_CIPHER_LINE_FORMAT = '        {cipher_name:<50}{error_message:<60}'

    def as_text(self) -> List[str]:
        result_txt = [self._format_title(self.scan_command.get_title())]

        # If we were able to connect, add some general comments about the cipher suite configuration
        if self.accepted_cipher_list:
            supports_forward_secrecy = False

            # All TLS 1.3 cipher suites support forward secrecy
            if isinstance(self.scan_command, Tlsv13ScanCommand):
                    supports_forward_secrecy = True
            else:
                for accepted_cipher in self.accepted_cipher_list:
                    if '_DHE_' in accepted_cipher.name or '_ECDHE_' in accepted_cipher.name:
                        supports_forward_secrecy = True
                        break

            result_txt.append(self._format_field(
                'Forward Secrecy',
                'OK - Supported' if supports_forward_secrecy else 'INSECURE - Not Supported',
            ))

            supports_rc4 = False
            for accepted_cipher in self.accepted_cipher_list:
                if '_RC4_' in accepted_cipher.name:
                    supports_rc4 = True
                    break
            result_txt.append(self._format_field(
                'RC4',
                'INSECURE - Supported' if supports_rc4 else 'OK - Not Supported',
            ))
            result_txt.append('')

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
            for accepted_cipher in self.accepted_cipher_list:
                result_txt.append(self._format_accepted_cipher_txt(accepted_cipher))
        elif self.scan_command.hide_rejected_ciphers:  # type: ignore
            result_txt.append('      Server rejected all cipher suites.')

        # Output all errors if any
        if len(self.errored_cipher_list) > 0:
            result_txt.append(self._format_subtitle('Undefined - An unexpected error happened:'))
            for err_cipher in self.errored_cipher_list:
                cipher_line_txt = self.REJECTED_CIPHER_LINE_FORMAT.format(cipher_name=err_cipher.name,
                                                                          error_message=err_cipher.error_message)
                result_txt.append(cipher_line_txt)

        # Output all rejected ciphers if needed
        if len(self.rejected_cipher_list) > 0 and not self.scan_command.hide_rejected_ciphers:  # type: ignore
            result_txt.append(self._format_subtitle('Rejected:'))
            for rejected_cipher in self.rejected_cipher_list:
                cipher_line_txt = self.REJECTED_CIPHER_LINE_FORMAT.format(
                    cipher_name=rejected_cipher.name,
                    error_message=rejected_cipher.handshake_error_message
                )
                result_txt.append(cipher_line_txt)

        return result_txt

    def _format_accepted_cipher_txt(self, cipher: AcceptedCipherSuite) -> str:
        keysize_str = '{} bits'.format(cipher.key_size) if cipher.key_size is not None else ''
        if cipher.is_anonymous:
            # Always display ANON as the key size for anonymous ciphers to make it visible
            keysize_str = 'ANONYMOUS'

        cipher_line_txt = self.ACCEPTED_CIPHER_LINE_FORMAT.format(
            cipher_name=cipher.name,
            dh_size='', key_size=keysize_str,
            status=cipher.post_handshake_response if cipher.post_handshake_response is not None else '',
        )
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
    "DHE-RSA-DES-CBC3-SHA": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "DHE-DSS-DES-CBC3-SHA": "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "AES128-CCM": "RSA_WITH_AES_128_CCM",
    "AES256-CCM": "RSA_WITH_AES_256_CCM",
    "DHE-RSA-AES128-CCM": "DHE_RSA_WITH_AES_128_CCM",
    "DHE-RSA-AES256-CCM": "TLS_DHE_RSA_WITH_AES_256_CCM",
    "AES128-CCM8": "RSA_WITH_AES_128_CCM_8",
    "AES256-CCM8": "RSA_WITH_AES_256_CCM_8",
    "DHE-RSA-AES128-CCM8": "DHE_RSA_WITH_AES_128_CCM_8",
    "DHE-RSA-AES256-CCM8": "DHE_RSA_WITH_AES_256_CCM_8",

    "ECDHE-ECDSA-AES128-CCM": "ECDHE_ECDSA_WITH_AES_128_CCM",
    "ECDHE-ECDSA-AES256-CCM": "ECDHE_ECDSA_WITH_AES_256_CCM",

    "ECDHE-ECDSA-AES128-CCM8": "ECDHE_ECDSA_WITH_AES_128_CCM_8",
    "ECDHE-ECDSA-AES256-CCM8": "ECDHE_ECDSA_WITH_AES_256_CCM_8",
}


OPENSSL_TO_RFC_NAMES_MAPPING: Dict[OpenSslVersionEnum, Dict[str, str]] = {
    OpenSslVersionEnum.SSLV2: SSLV2_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.SSLV3: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1_1: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1_2: TLS_OPENSSL_TO_RFC_NAMES_MAPPING,
    OpenSslVersionEnum.TLSV1_3: {},  # For TLS 1.3, OpenSSL directly uses the RFC names
}
