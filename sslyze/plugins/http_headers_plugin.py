from xml.etree.ElementTree import Element

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, load_pem_x509_certificate

from sslyze.plugins.plugin_base import PluginScanCommand, Plugin, PluginScanResult
from sslyze.plugins.utils.certificate_utils import CertificateUtils
from sslyze.plugins.utils.trust_store.trust_store import CouldNotBuildVerifiedChainError
from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.utils.http_request_generator import HttpRequestGenerator
from sslyze.utils.http_response_parser import HttpResponseParser
from typing import List, Type, Tuple, Optional, Dict, Any


class HttpHeadersScanCommand(PluginScanCommand):
    """Check for the HTTP Strict Transport Security (HSTS) and HTTP Public Key Pinning (HPKP) HTTP headers within the
    response sent back by the server(s). Also compute the HPKP pins for the server(s)' current certificate chain.
    """

    @classmethod
    def get_cli_argument(cls) -> str:
        return 'http_headers'

    @classmethod
    def get_title(cls) -> str:
        return 'HTTP Security Headers'


class HttpHeadersPlugin(Plugin):
    """Test the server(s) for the presence of security-related HTTP headers.
    """

    @classmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        return [HttpHeadersScanCommand]

    def process_task(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: PluginScanCommand
    ) -> 'HttpHeadersScanResult':
        if not isinstance(scan_command, HttpHeadersScanCommand):
            raise ValueError('Unexpected scan command')

        if server_info.tls_wrapped_protocol not in [TlsWrappedProtocolEnum.PLAIN_TLS, TlsWrappedProtocolEnum.HTTPS]:
            raise ValueError('Cannot test for HTTP headers on a StartTLS connection.')

        hsts_header, hpkp_header, expect_ct_header, hpkp_report_only, certificate_chain = self._get_security_headers(
            server_info
        )
        return HttpHeadersScanResult(server_info, scan_command, hsts_header, hpkp_header, expect_ct_header,
                                     hpkp_report_only, certificate_chain)

    @classmethod
    def _get_security_headers(
            cls,
            server_info: ServerConnectivityInfo
    ) -> Tuple[Optional[str], Optional[str], Optional[str], bool, List[Certificate]]:
        hpkp_report_only = False

        # Perform the SSL handshake
        ssl_connection = server_info.get_preconfigured_ssl_connection()
        try:
            ssl_connection.connect()
            certificate_chain = [
                load_pem_x509_certificate(x509_cert.as_pem().encode('ascii'), backend=default_backend())
                for x509_cert in ssl_connection.ssl_client.get_peer_cert_chain()
            ]
            # Send an HTTP GET request to the server
            ssl_connection.ssl_client.write(HttpRequestGenerator.get_request(host=server_info.hostname))
            http_resp = HttpResponseParser.parse_from_ssl_connection(ssl_connection.ssl_client)
        finally:
            ssl_connection.close()

        if http_resp.version == 9:
            # HTTP 0.9 => Probably not an HTTP response
            raise ValueError('Server did not return an HTTP response')
        else:
            hsts_header = http_resp.getheader('strict-transport-security', None)
            hpkp_header = http_resp.getheader('public-key-pins', None)
            expect_ct_header = http_resp.getheader('expect-ct', None)
            if hpkp_header is None:
                hpkp_report_only = True
                hpkp_header = http_resp.getheader('public-key-pins-report-only', None)

        # We do not follow redirections because the security headers must be set on the first page according to
        # https://hstspreload.appspot.com/:
        # "If you are serving an additional redirect from your HTTPS site, that redirect must still have the HSTS
        # header (rather than the page it redirects to)."
        return hsts_header, hpkp_header, expect_ct_header, hpkp_report_only, certificate_chain


class ParsedHstsHeader:
    """The HTTP Strict Transport Security header returned by the server.

    Attributes:
        preload (bool): True if the preload directive is set.
        include_subdomains (bool): True if the includesubdomains directive is set.
        max_age (int): The content of the max-age field.
    """
    def __init__(self, raw_hsts_header: str) -> None:
        # Handle headers defined multiple times by picking the first value
        if ',' in raw_hsts_header:
            raw_hsts_header = raw_hsts_header.split(',')[0]

        self.max_age = None
        self.include_subdomains = False
        self.preload = False
        for hsts_directive in raw_hsts_header.split(';'):
            hsts_directive = hsts_directive.strip()
            if not hsts_directive:
                # Empty space at the end of the header
                continue

            if 'max-age' in hsts_directive:
                self.max_age = int(hsts_directive.split('max-age=')[1].strip())
            elif 'includesubdomains' in hsts_directive.lower():
                # Some websites have a different case for IncludeSubDomains
                self.include_subdomains = True
            elif 'preload' in hsts_directive:
                self.preload = True
            else:
                raise ValueError('Unexpected value in HSTS header: {}'.format(repr(hsts_directive)))


class ParsedHpkpHeader:
    """The HTTP Public Key Pinning header returned by the server.

    Attributes:
        report_only (bool): True if the HPKP header used is "Public-Key-Pins-Report-Only" (instead of
            "Public-Key-Pins").
        report_uri (str): The content of the report-uri field.
        include_subdomains (bool): True if the includesubdomains directive is set.
        max_age (int): The content of the max-age field.
        pin_sha256_list (List[str]): The list of pin-sha256 values set in the header.
    """

    def __init__(self, raw_hpkp_header: str, report_only: bool = False) -> None:
        # Handle headers defined multiple times by picking the first value
        if ',' in raw_hpkp_header:
            raw_hpkp_header = raw_hpkp_header.split(',')[0]

        self.report_only = report_only
        self.report_uri = None
        self.include_subdomains = False
        self.max_age = None

        pin_sha256_list = []
        for hpkp_directive in raw_hpkp_header.split(';'):
            hpkp_directive = hpkp_directive.strip()
            if not hpkp_directive:
                # Empty space at the end of the header
                continue

            if 'pin-sha256' in hpkp_directive:
                pin_sha256_list.append(hpkp_directive.split('pin-sha256=')[1].strip(' "'))
            elif 'max-age' in hpkp_directive:
                self.max_age = int(hpkp_directive.split('max-age=')[1].strip())
            elif 'includesubdomains' in hpkp_directive.lower():
                # Some websites have a different case for IncludeSubDomains
                self.include_subdomains = True
            elif 'report-uri' in hpkp_directive:
                self.report_uri = hpkp_directive.split('report-uri=')[1].strip(' "')
            else:
                raise ValueError('Unexpected value in HPKP header: {}'.format(repr(hpkp_directive)))

        self.pin_sha256_list = pin_sha256_list


# TODO(AD): Rename this to ParsedExpectCtHeader
class ParsedExpectCtHeader:
    """Expect-CT header returned by the server.

    Attributes:
        max-age (int): The content of the max-age field.
        report-uri (str): The content of report-uri field.
        enforce (bool): True if enforce directive is set.
    """

    def __init__(self, raw_expect_ct_header: str) -> None:
        self.max_age = None
        self.report_uri = None
        self.enforce = False

        for expect_ct_directive in raw_expect_ct_header.split(','):
            expect_ct_directive = expect_ct_directive.strip()

            if not expect_ct_directive:
                continue

            if 'max-age' in expect_ct_directive:
                self.max_age = int(expect_ct_directive.split('max-age=')[1].strip())
            elif 'report-uri' in expect_ct_directive:
                self.report_uri = expect_ct_directive.split('report-uri=')[1].strip(' "')
            elif 'enforce' in expect_ct_directive:
                self.enforce = True
            else:
                raise ValueError('Unexpected value in Expect-CT header: {}'.format(repr(expect_ct_directive)))


class HttpHeadersScanResult(PluginScanResult):
    """The result of running a HttpHeadersScanCommand on a specific server.

    Attributes:
        hsts_header (Optional[ParsedHstsHeader]): The content of the HSTS header returned by the server; None if no HSTS
            header was returned.
        hpkp_header (Optional[ParsedHpkpHeader]): The content of the HPKP header returned by the server; None if no HPKP
            header was returned.
        expect_ct_header (Optional[ParsedExpectCTHeader]): The content of the Expect-CT header returned by the server;
            None if no Expect-CT header was returned.
        is_valid_pin_configured (Optional[bool]): True if at least one of the configured pins was found in the server's
            verified certificate chain. None if the verified chain could not be built or no HPKP header was returned.
        is_backup_pin_configured (Optional[bool]): True if if at least one of the configured pins was NOT found in the
            server's verified certificate chain. None if the verified chain could not be built or no HPKP header was
            returned.
        verified_certificate_chain (List[cryptography.x509.Certificate]): The verified certificate chain; index 0 is the
            leaf certificate and the last element is the anchor/CA certificate from the Mozilla trust store. Will be
            empty if validation failed or the verified chain could not be built. The HPKP pin for each certificate is
            available in the certificate's hpkp_pin attribute. None if the verified chain could not be built. Each
            certificate is parsed using the cryptography module; documentation is available at
            https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object.
    """

    def __init__(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: HttpHeadersScanCommand,
            raw_hsts_header: Optional[str],
            raw_hpkp_header: Optional[str],
            raw_expect_ct_header: Optional[str],
            hpkp_report_only: bool,
            cert_chain: List[Certificate],
    ) -> None:
        super().__init__(server_info, scan_command)
        self.hsts_header = ParsedHstsHeader(raw_hsts_header) if raw_hsts_header else None
        self.hpkp_header = ParsedHpkpHeader(raw_hpkp_header, hpkp_report_only) if raw_hpkp_header else None
        self.expect_ct_header = ParsedExpectCtHeader(raw_expect_ct_header) if raw_expect_ct_header else None
        self.verified_certificate_chain: List[Certificate] = []
        try:
            main_trust_store = TrustStoresRepository.get_default().get_main_store()
            self.verified_certificate_chain = main_trust_store.build_verified_certificate_chain(cert_chain)
        except CouldNotBuildVerifiedChainError:
            pass

        # Is the pinning configuration valid?
        self.is_valid_pin_configured = None
        self.is_backup_pin_configured = None
        if self.verified_certificate_chain and self.hpkp_header:
            # Is one of the configured pins in the current server chain?
            self.is_valid_pin_configured = False
            server_pin_list = [CertificateUtils.get_hpkp_pin(cert) for cert in self.verified_certificate_chain]
            for pin in self.hpkp_header.pin_sha256_list:
                if pin in server_pin_list:
                    self.is_valid_pin_configured = True
                    break

            # Is a backup pin configured?
            self.is_backup_pin_configured = set(self.hpkp_header.pin_sha256_list) != set(server_pin_list)

    def __getstate__(self) -> Dict[str, Any]:
        # This object needs to be pick-able as it gets sent through multiprocessing.Queues
        pickable_dict = self.__dict__.copy()
        # Manually handle non-pickable entries
        pem_verified_chain = [cert.public_bytes(Encoding.PEM) for cert in pickable_dict['verified_certificate_chain']]
        pickable_dict['verified_certificate_chain'] = pem_verified_chain
        return pickable_dict

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        # Manually restore non-pickable entries
        verified_chain = [load_pem_x509_certificate(cert_pem, default_backend())
                          for cert_pem in self.__dict__['verified_certificate_chain']]
        self.__dict__['verified_certificate_chain'] = verified_chain

    PIN_TXT_FORMAT = '      {0:<50}{1}'.format

    def as_text(self) -> List[str]:
        txt_result = [self._format_title(self.scan_command.get_title())]

        if self.hsts_header:
            txt_result.append(self._format_subtitle('HTTP Strict Transport Security (HSTS)'))
            txt_result.append(self._format_field("Max Age:", str(self.hsts_header.max_age)))
            txt_result.append(self._format_field("Include Subdomains:", str(self.hsts_header.include_subdomains)))
            txt_result.append(self._format_field("Preload:", str(self.hsts_header.preload)))
        else:
            txt_result.append(self._format_field("NOT SUPPORTED - Server did not send an HSTS header", ""))

        computed_hpkp_pins_text = ['', self._format_subtitle('Computed HPKP Pins for Current Chain')]
        if self.verified_certificate_chain:
            for index, cert in enumerate(self.verified_certificate_chain, start=0):
                final_subject = CertificateUtils.get_name_as_short_text(cert.subject)
                if len(final_subject) > 40:
                    # Make the CN shorter when displaying it
                    final_subject = '{}...'.format(final_subject[:40])
                computed_hpkp_pins_text.append(
                    self.PIN_TXT_FORMAT(('{} - {}'.format(index, final_subject)), CertificateUtils.get_hpkp_pin(cert))
                )
        else:
            computed_hpkp_pins_text.append(
                self._format_field('ERROR - Could not build verified chain (certificate untrusted?)', '')
            )

        txt_result.extend(['', self._format_subtitle('HTTP Public Key Pinning (HPKP)')])
        if self.hpkp_header:
            txt_result.append(self._format_field("Max Age:", str(self.hpkp_header.max_age)))
            txt_result.append(self._format_field("Include Subdomains:", str(self.hpkp_header.include_subdomains)))
            txt_result.append(self._format_field("Report URI:", str(self.hpkp_header.report_uri)))
            txt_result.append(self._format_field("Report Only:", str(self.hpkp_header.report_only)))
            txt_result.append(self._format_field("SHA-256 Pin List:", ', '.join(self.hpkp_header.pin_sha256_list)))

            if self.verified_certificate_chain:
                pin_validation_txt = 'OK - One of the configured pins was found in the certificate chain' \
                    if self.is_valid_pin_configured \
                    else 'FAILED - Could NOT find any of the configured pins in the certificate chain!'
                txt_result.append(self._format_field("Valid Pin:", pin_validation_txt))

                backup_txt = 'OK - Backup pin found in the configured pins' \
                    if self.is_backup_pin_configured \
                    else 'FAILED - No backup pin found: all the configured pins are in the certificate chain!'
                txt_result.append(self._format_field("Backup Pin:", backup_txt))

        else:
            txt_result.append(self._format_field("NOT SUPPORTED - Server did not send an HPKP header", ""))

        # Dislpay computed HPKP pins
        txt_result.extend(computed_hpkp_pins_text)

        txt_result.extend(['', self._format_subtitle('HTTP Expect-CT')])
        if self.expect_ct_header:
            txt_result.append(self._format_field('Max Age:', str(self.expect_ct_header.max_age)))
            txt_result.append(self._format_field('Report- URI:', str(self.expect_ct_header.report_uri)))
            txt_result.append(self._format_field('Enforce:', str(self.expect_ct_header.enforce)))
        else:
            txt_result.append(self._format_field("NOT SUPPORTED - Server did not send an Expect-CT header", ""))

        return txt_result

    def as_xml(self) -> Element:
        xml_result = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())

        # HSTS header
        if self.hsts_header is None:
            xml_hsts_attr = {
                'isSupported': str(False)
            }
        else:
            xml_hsts_attr = {
                'isSupported': str(True),
                'maxAge': str(self.hsts_header.max_age),
                'includeSubDomains': str(self.hsts_header.include_subdomains),
                'preload': str(self.hsts_header.preload)
            }

        xml_hsts = Element('httpStrictTransportSecurity', attrib=xml_hsts_attr)
        xml_result.append(xml_hsts)

        # HPKP header
        xml_pin_list = []
        if self.hpkp_header is None:
            xml_hpkp_attr = {
                'isSupported': str(False)
            }
        else:
            xml_hpkp_attr = {
                'isSupported': str(True),
                'maxAge': str(self.hpkp_header.max_age),
                'includeSubDomains': str(self.hpkp_header.include_subdomains),
                'reportOnly': str(self.hpkp_header.report_only),
                'reportUri': str(self.hpkp_header.report_uri)
            }

            if self.verified_certificate_chain:
                xml_hpkp_attr['isValidPinConfigured'] = str(self.is_valid_pin_configured)
                xml_hpkp_attr['isBackupPinConfigured'] = str(self.is_backup_pin_configured)

            for pin in self.hpkp_header.pin_sha256_list:
                xml_pin = Element('pinSha256')
                xml_pin.text = pin
                xml_pin_list.append(xml_pin)

        xml_hpkp = Element('httpPublicKeyPinning', attrib=xml_hpkp_attr)
        for xml_pin in xml_pin_list:
            xml_hpkp.append(xml_pin)
        xml_result.append(xml_hpkp)

        # Expect-CT header
        if self.expect_ct_header is not None:
            xml_expect_ct_attr = {
                'isSupported': str(True),
                'maxAge': str(self.expect_ct_header.max_age),
                'reportUri': str(self.expect_ct_header.report_uri),
                'enforce': str(self.expect_ct_header.enforce)
            }
        else:
            xml_expect_ct_attr = {
                'isSupported': str(False)
            }

        xml_expect_ct = Element('httpExpectCT', attrib=xml_expect_ct_attr)
        xml_result.append(xml_expect_ct)

        return xml_result
