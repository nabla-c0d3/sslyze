from http.client import HTTPResponse
from xml.etree.ElementTree import Element

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, load_pem_x509_certificate
from dataclasses import dataclass
from nassl.ssl_client import CouldNotBuildVerifiedChain

from sslyze.plugins.plugin_base import PluginScanCommand, Plugin, PluginScanResult
from sslyze.plugins.utils.certificate_utils import CertificateUtils
from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.utils.http_request_generator import HttpRequestGenerator
from sslyze.utils.http_response_parser import HttpResponseParser
from typing import List, Type, Optional, Dict, Any, TypeVar


class HttpHeadersScanCommand(PluginScanCommand):
    """Check for the HTTP Strict Transport Security (HSTS) and HTTP Public Key Pinning (HPKP) HTTP headers within the
    response sent back by the server(s). Also compute the HPKP pins for the server(s)' current certificate chain.
    """

    @classmethod
    def get_cli_argument(cls) -> str:
        return "http_headers"

    @classmethod
    def get_title(cls) -> str:
        return "HTTP Security Headers"


class HttpHeadersPlugin(Plugin):
    """Test the server(s) for the presence of security-related HTTP headers.
    """

    @classmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        return [HttpHeadersScanCommand]

    def process_task(
        self, server_info: ServerConnectivityInfo, scan_command: PluginScanCommand
    ) -> "HttpHeadersScanResult":
        if not isinstance(scan_command, HttpHeadersScanCommand):
            raise ValueError("Unexpected scan command")

        if server_info.tls_wrapped_protocol not in [TlsWrappedProtocolEnum.PLAIN_TLS, TlsWrappedProtocolEnum.HTTPS]:
            raise ValueError("Cannot test for HTTP headers on a StartTLS connection.")

        # Perform the SSL handshake
        mozilla_store = TrustStoresRepository.get_default().get_main_store()
        ssl_connection = server_info.get_preconfigured_ssl_connection(ssl_verify_locations=mozilla_store.path)
        try:
            ssl_connection.connect()
            try:
                verified_chain_as_pem = ssl_connection.ssl_client.get_verified_chain()
            except CouldNotBuildVerifiedChain:
                verified_chain_as_pem = None
            except AttributeError:
                # Only the modern SSL Client can build the verified chain; hence we get here if the server only supports
                # an older version of TLS (pre 1.2)
                verified_chain_as_pem = None

            # Send an HTTP GET request to the server
            ssl_connection.ssl_client.write(HttpRequestGenerator.get_request(host=server_info.hostname))

            # We do not follow redirections because the security headers must be set on the first page according to
            # https://hstspreload.appspot.com/:
            # "If you are serving an additional redirect from your HTTPS site, that redirect must still have the HSTS
            # header (rather than the page it redirects to)."
            http_response = HttpResponseParser.parse_from_ssl_connection(ssl_connection.ssl_client)
        finally:
            ssl_connection.close()

        if http_response.version == 9:
            # HTTP 0.9 => Probably not an HTTP response
            raise ValueError("Server did not return an HTTP response")

        # Parse the certificate chain
        verified_chain = (
            [
                load_pem_x509_certificate(cert_as_pem.encode("ascii"), backend=default_backend())
                for cert_as_pem in verified_chain_as_pem
            ]
            if verified_chain_as_pem
            else None
        )

        # Parse each header
        hsts_header = StrictTransportSecurityHeader.from_http_response(http_response)
        expect_ct_header = ExpectCtHeader.from_http_response(http_response)
        hpkp_header = PublicKeyPinsHeader.from_http_response(http_response)
        hpkp_report_only_header = PublicKeyPinsReportOnlyHeader.from_http_response(http_response)

        return HttpHeadersScanResult(
            server_info,
            scan_command,
            hsts_header,
            hpkp_header,
            hpkp_report_only_header,
            expect_ct_header,
            verified_chain,
        )


def _extract_first_header_value(response: HTTPResponse, header_name: str) -> Optional[str]:
    raw_header = response.getheader(header_name, None)
    if not raw_header:
        return None

    # Handle headers defined multiple times by picking the first value
    if "," in raw_header:
        raw_header = raw_header.split(",")[0]
    return raw_header


@dataclass
class StrictTransportSecurityHeader:
    """A Strict-Transport-Security header parsed from a server's HTTP response.

    Attributes:
        preload (bool): True if the preload directive is set.
        include_subdomains (bool): True if the includesubdomains directive is set.
        max_age (Optional[int]): The content of the max-age field.
    """

    max_age: Optional[int]
    preload: bool
    include_subdomains: bool

    @classmethod
    def from_http_response(cls, response: HTTPResponse) -> Optional["StrictTransportSecurityHeader"]:
        raw_hsts_header = _extract_first_header_value(response, "strict-transport-security")
        if not raw_hsts_header:
            return None

        max_age = None
        include_subdomains = False
        preload = False
        for hsts_directive in raw_hsts_header.split(";"):
            hsts_directive = hsts_directive.strip()
            if not hsts_directive:
                # Empty space at the end of the header
                continue

            if "max-age" in hsts_directive:
                max_age = int(hsts_directive.split("max-age=")[1].strip())
            elif "includesubdomains" in hsts_directive.lower():
                # Some websites have a different case for IncludeSubDomains
                include_subdomains = True
            elif "preload" in hsts_directive:
                preload = True
            else:
                raise ValueError(f"Unexpected value in HSTS header: {repr(hsts_directive)}")

        return cls(max_age, preload, include_subdomains)


_T = TypeVar("_T", bound="PublicKeyPinsHeader")


@dataclass
class PublicKeyPinsHeader:
    """A Public-Key-Pins header parsed from a server's HTTP response.

    Attributes:
        include_subdomains (bool): True if the includesubdomains directive is set.
        max_age (Optional[int]): The content of the max-age field.
        pin_sha256_list (List[str]): The list of pin-sha256 values set in the header.
        report_uri (Optional[str]): The content of the report-uri field.
        report_to (Optional[str]): The content of the report-to field, available via the Reporting API as described at
            https://w3c.github.io/reporting/#examples.
    """

    max_age: Optional[int]
    pin_sha256_list: List[str]
    include_subdomains: bool
    report_uri: Optional[str]
    report_to: Optional[str]

    @classmethod
    def from_http_response(cls: Type[_T], response: HTTPResponse) -> Optional[_T]:
        raw_hpkp_header = _extract_first_header_value(response, "public-key-pins")
        if not raw_hpkp_header:
            return None
        return cls._from_header(raw_hpkp_header)

    @classmethod
    def _from_header(cls: Type[_T], raw_hpkp_header: str) -> _T:
        report_uri = None
        include_subdomains = False
        max_age = None
        report_to = None
        pin_sha256_list = []
        for hpkp_directive in raw_hpkp_header.split(";"):
            hpkp_directive = hpkp_directive.strip()
            if not hpkp_directive:
                # Empty space at the end of the header
                continue

            if "pin-sha256" in hpkp_directive:
                pin_sha256_list.append(hpkp_directive.split("pin-sha256=")[1].strip(' "'))
            elif "max-age" in hpkp_directive:
                max_age = int(hpkp_directive.split("max-age=")[1].strip())
            elif "includesubdomains" in hpkp_directive.lower():
                # Some websites have a different case for IncludeSubDomains
                include_subdomains = True
            elif "report-uri" in hpkp_directive:
                report_uri = hpkp_directive.split("report-uri=")[1].strip(' "')
            elif "report-to" in hpkp_directive:
                # Reporting API `report-to` group name; https://w3c.github.io/reporting/#examples
                report_to = hpkp_directive.split("report-to=")[1].strip(' "')
            else:
                raise ValueError(f"Unexpected value in HPKP header: {repr(hpkp_directive)}")

        return cls(max_age, pin_sha256_list, include_subdomains, report_uri, report_to)


@dataclass
class PublicKeyPinsReportOnlyHeader(PublicKeyPinsHeader):
    """A Public-Key-Pins-Report-Only header parsed from a server's HTTP response.

    Attributes:
        include_subdomains (bool): True if the includesubdomains directive is set.
        max_age (Optional[int]): The content of the max-age field.
        pin_sha256_list (List[str]): The list of pin-sha256 values set in the header.
        report_uri (Optional[str]): The content of the report-uri field.
        report_to (Optional[str]): The content of the report-to field, available via the Reporting API as described at
            https://w3c.github.io/reporting/#examples.
    """

    @classmethod
    def from_http_response(cls: Type[_T], response: HTTPResponse) -> Optional[_T]:
        raw_hpkp_report_only_header = _extract_first_header_value(response, "public-key-pins-report-only")
        if not raw_hpkp_report_only_header:
            return None
        return cls._from_header(raw_hpkp_report_only_header)


@dataclass
class ExpectCtHeader:
    """An Expect-CT header parsed from a server's HTTP response.

    Attributes:
        max-age (Optional[int]): The content of the max-age field.
        report-uri (Optional[str]): The content of report-uri field.
        enforce (bool): True if enforce directive is set.
    """

    max_age: Optional[int]
    report_uri: Optional[str]
    enforce: bool

    @classmethod
    def from_http_response(cls, response: HTTPResponse) -> Optional["ExpectCtHeader"]:
        raw_expect_ct_header = _extract_first_header_value(response, "expect-ct")
        if not raw_expect_ct_header:
            return None

        max_age = None
        report_uri = None
        enforce = False
        for expect_ct_directive in raw_expect_ct_header.split(","):
            expect_ct_directive = expect_ct_directive.strip()

            if not expect_ct_directive:
                continue

            if "max-age" in expect_ct_directive:
                max_age = int(expect_ct_directive.split("max-age=")[1].strip())
            elif "report-uri" in expect_ct_directive:
                report_uri = expect_ct_directive.split("report-uri=")[1].strip(' "')
            elif "enforce" in expect_ct_directive:
                enforce = True
            else:
                raise ValueError(f"Unexpected value in Expect-CT header: {repr(expect_ct_directive)}")

        return cls(max_age, report_uri, enforce)


class HttpHeadersScanResult(PluginScanResult):
    """The result of running a HttpHeadersScanCommand on a specific server.

    Each HTTP header described below will be None if the server did not return it.

    Attributes:
        strict_transport_security_header (Optional[StrictTransportSecurityHeader]): The Strict-Transport-Security
            header returned by the server.
        public_key_pins_header (Optional[PublicKeyPinsHeader]): The Public-Key-Pins header returned by the server.
        public_key_pins_report_only_header (Optional[PublicKeyPinsReportOnlyHeader]): The Public-Key-Pins-Report-Only
            header returned by the server.
        expect_ct_header (Optional[ExpectCtHeader]): The Expect-CT header returned by the server.
        is_valid_pin_configured (Optional[bool]): True if at least one of the configured pins was found in the server's
            verified certificate chain. None if the verified chain could not be built or no HPKP header was returned.
        is_backup_pin_configured (Optional[bool]): True if if at least one of the configured pins was NOT found in the
            server's verified certificate chain. None if the verified chain could not be built or no HPKP header was
            returned.
        verified_certificate_chain (Optional[List[cryptography.x509.Certificate]]): The verified certificate chain;
            index 0 is the leaf certificate and the last element is the anchor/CA certificate from the Mozilla trust
            store. Will be `None` if validation failed or the verified chain could not be built. The HPKP pin for each
            certificate is available in the certificate's hpkp_pin attribute.
            Each certificate is parsed using the cryptography module; documentation is available at
            https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object.
    """

    def __init__(
        self,
        server_info: ServerConnectivityInfo,
        scan_command: HttpHeadersScanCommand,
        strict_transport_security_header: Optional[StrictTransportSecurityHeader],
        public_key_pins_header: Optional[PublicKeyPinsHeader],
        public_key_pins_report_only_header: Optional[PublicKeyPinsReportOnlyHeader],
        expect_ct_header: Optional[ExpectCtHeader],
        verified_chain: Optional[List[Certificate]],
    ) -> None:
        super().__init__(server_info, scan_command)
        self.strict_transport_security_header = strict_transport_security_header
        self.public_key_pins_header = public_key_pins_header
        self.public_key_pins_report_only_header = public_key_pins_report_only_header
        self.expect_ct_header = expect_ct_header
        self.verified_certificate_chain = verified_chain

        # Is the pinning configuration valid?
        self.is_valid_pin_configured = None
        self.is_backup_pin_configured = None

        returned_hpkp_header = None
        if self.public_key_pins_header:
            returned_hpkp_header = self.public_key_pins_header
        elif self.public_key_pins_report_only_header:
            returned_hpkp_header = self.public_key_pins_report_only_header

        if self.verified_certificate_chain and returned_hpkp_header:
            # Is one of the configured pins in the current server chain?
            self.is_valid_pin_configured = False
            server_pin_list = [CertificateUtils.get_hpkp_pin(cert) for cert in self.verified_certificate_chain]
            for pin in returned_hpkp_header.pin_sha256_list:
                if pin in server_pin_list:
                    self.is_valid_pin_configured = True
                    break

            # Is a backup pin configured?
            self.is_backup_pin_configured = set(returned_hpkp_header.pin_sha256_list) != set(server_pin_list)

    def __getstate__(self) -> Dict[str, Any]:
        # This object needs to be pick-able as it gets sent through multiprocessing.Queues
        pickable_dict = self.__dict__.copy()
        # Manually handle non-pickable entries
        if pickable_dict["verified_certificate_chain"]:
            pickable_dict["verified_certificate_chain"] = [
                cert.public_bytes(Encoding.PEM) for cert in pickable_dict["verified_certificate_chain"]
            ]
        return pickable_dict

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        # Manually restore non-pickable entries
        if self.__dict__["verified_certificate_chain"]:
            self.__dict__["verified_certificate_chain"] = [
                load_pem_x509_certificate(cert_pem, default_backend())
                for cert_pem in self.__dict__["verified_certificate_chain"]
            ]

    _PIN_TXT_FORMAT = "      {0:<50}{1}".format
    _HEADER_NOT_SENT_TXT = "NOT SUPPORTED - Server did not return the header"

    def as_text(self) -> List[str]:
        txt_result = [self._format_title(self.scan_command.get_title()), ""]

        txt_result.append(self._format_subtitle("Computed HPKP Pins for Server Certificate Chain"))
        if self.verified_certificate_chain:
            for index, cert in enumerate(self.verified_certificate_chain, start=0):
                final_subject = CertificateUtils.get_name_as_short_text(cert.subject)
                if len(final_subject) > 40:
                    # Make the CN shorter when displaying it
                    final_subject = "{}...".format(final_subject[:40])
                txt_result.append(
                    self._PIN_TXT_FORMAT(("{} - {}".format(index, final_subject)), CertificateUtils.get_hpkp_pin(cert))
                )
                txt_result.append("")
        else:
            txt_result.append(self._format_field("ERROR - Could not build verified chain (certificate untrusted?)", ""))
            txt_result.append("")

        txt_result.append(self._format_subtitle("Strict-Transport-Security Header"))
        if self.strict_transport_security_header:
            txt_result.append(self._format_field("Max Age:", str(self.strict_transport_security_header.max_age)))
            txt_result.append(
                self._format_field("Include Subdomains:", str(self.strict_transport_security_header.include_subdomains))
            )
            txt_result.append(self._format_field("Preload:", str(self.strict_transport_security_header.preload)))
        else:
            txt_result.append(self._format_field(self._HEADER_NOT_SENT_TXT, ""))

        for header, subtitle in [
            (self.public_key_pins_header, "Public-Key-Pins Header"),
            (self.public_key_pins_report_only_header, "Public-Key-Pins-Report-Only Header"),
        ]:
            txt_result.extend(["", self._format_subtitle(subtitle)])
            if header:
                txt_result.append(self._format_field("Max Age:", str(header.max_age)))
                txt_result.append(self._format_field("Include Subdomains:", str(header.include_subdomains)))
                txt_result.append(self._format_field("Report URI:", str(header.report_uri)))
                txt_result.append(self._format_field("SHA-256 Pin List:", ", ".join(header.pin_sha256_list)))

                if self.verified_certificate_chain:
                    pin_validation_txt = (
                        "OK - One of the configured pins was found in the certificate chain"
                        if self.is_valid_pin_configured
                        else "FAILED - Could NOT find any of the configured pins in the certificate chain!"
                    )
                    txt_result.append(self._format_field("Valid Pin:", pin_validation_txt))

                    backup_txt = (
                        "OK - Backup pin found in the configured pins"
                        if self.is_backup_pin_configured
                        else "FAILED - No backup pin found: all the configured pins are in the certificate chain!"
                    )
                    txt_result.append(self._format_field("Backup Pin:", backup_txt))

            else:
                txt_result.append(self._format_field(self._HEADER_NOT_SENT_TXT, ""))

        txt_result.extend(["", self._format_subtitle("Expect-CT Header")])
        if self.expect_ct_header:
            txt_result.append(self._format_field("Max Age:", str(self.expect_ct_header.max_age)))
            txt_result.append(self._format_field("Report- URI:", str(self.expect_ct_header.report_uri)))
            txt_result.append(self._format_field("Enforce:", str(self.expect_ct_header.enforce)))
        else:
            txt_result.append(self._format_field(self._HEADER_NOT_SENT_TXT, ""))

        return txt_result

    def as_xml(self) -> Element:
        xml_result = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())

        # HSTS header
        if self.strict_transport_security_header is None:
            xml_hsts_attr = {"isSupported": str(False)}
        else:
            xml_hsts_attr = {
                "isSupported": str(True),
                "maxAge": str(self.strict_transport_security_header.max_age),
                "includeSubDomains": str(self.strict_transport_security_header.include_subdomains),
                "preload": str(self.strict_transport_security_header.preload),
            }

        xml_hsts = Element("strictTransportSecurity", attrib=xml_hsts_attr)
        xml_result.append(xml_hsts)

        # HPKP headers
        for header, xml_name in [
            (self.public_key_pins_header, "publicKeyPins"),
            (self.public_key_pins_report_only_header, "publicKeyPinsReportOnly"),
        ]:
            xml_pin_list = []
            if header is None:
                xml_hpkp_attr = {"isSupported": str(False)}
            else:
                xml_hpkp_attr = {
                    "isSupported": str(True),
                    "maxAge": str(header.max_age),
                    "includeSubDomains": str(header.include_subdomains),
                    "reportUri": str(header.report_uri),
                }

                if self.verified_certificate_chain:
                    xml_hpkp_attr["isValidPinConfigured"] = str(self.is_valid_pin_configured)
                    xml_hpkp_attr["isBackupPinConfigured"] = str(self.is_backup_pin_configured)

                for pin in self.public_key_pins_header.pin_sha256_list:  # type: ignore
                    xml_pin = Element("pinSha256")
                    xml_pin.text = pin
                    xml_pin_list.append(xml_pin)

            xml_hpkp = Element(xml_name, attrib=xml_hpkp_attr)
            for xml_pin in xml_pin_list:
                xml_hpkp.append(xml_pin)
            xml_result.append(xml_hpkp)

        # Expect-CT header
        if self.expect_ct_header is not None:
            xml_expect_ct_attr = {
                "isSupported": str(True),
                "maxAge": str(self.expect_ct_header.max_age),
                "reportUri": str(self.expect_ct_header.report_uri),
                "enforce": str(self.expect_ct_header.enforce),
            }
        else:
            xml_expect_ct_attr = {"isSupported": str(False)}

        xml_expect_ct = Element("expectCt", attrib=xml_expect_ct_attr)
        xml_result.append(xml_expect_ct)

        return xml_result
