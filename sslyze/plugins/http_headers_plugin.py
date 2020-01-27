from concurrent.futures._base import Future
from http.client import HTTPResponse

from dataclasses import dataclass

from sslyze.plugins.plugin_base import ScanCommandImplementation, ScanCommandExtraArguments, ScanJob, ScanCommandResult
from sslyze.plugins.utils.certificate_utils import CertificateUtils
from sslyze.server_connectivity_tester import ServerConnectivityInfo
from sslyze.utils.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum
from sslyze.utils.http_request_generator import HttpRequestGenerator
from sslyze.utils.http_response_parser import HttpResponseParser
from typing import List, Type, Optional, TypeVar


@dataclass(frozen=True)
class HttpHeadersScanResult(ScanCommandResult):
    """The result of testing a server for HTTP headers related to security.

    Each HTTP header described below will be None if the server did not return it.

    Attributes:
        strict_transport_security_header: The Strict-Transport-Security header returned by the server.
        public_key_pins_header: The Public-Key-Pins header returned by the server.
        public_key_pins_report_only_header: The Public-Key-Pins-Report-Only header returned by the server.
        expect_ct_header: The Expect-CT header returned by the server.
    """

    strict_transport_security_header: Optional["StrictTransportSecurityHeader"]

    public_key_pins_header: Optional["PublicKeyPinsHeader"]
    public_key_pins_report_only_header: Optional["PublicKeyPinsReportOnlyHeader"]

    expect_ct_header: Optional["ExpectCtHeader"]


class HttpHeadersImplementation(ScanCommandImplementation):
    """Test a server for HTTP headers related to security, including HSTS and HPKP.
    """

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ValueError("This plugin does not take extra arguments")

        if server_info.network_configuration.tls_opportunistic_encryption:
            raise ValueError("Cannot test for HTTP headers on a StartTLS connection.")

        return [ScanJob(function_to_call=_retrieve_and_analyze_http_response, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> ScanCommandResult:
        if len(completed_scan_jobs) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {completed_scan_jobs}")

        return completed_scan_jobs[0].result()


def _retrieve_and_analyze_http_response(server_info: ServerConnectivityInfo) -> HttpHeadersScanResult:
    # Perform the TLS handshake
    ssl_connection = server_info.get_preconfigured_ssl_connection()
    try:
        ssl_connection.connect()

        # Send an HTTP GET request to the server
        ssl_connection.ssl_client.write(
            HttpRequestGenerator.get_request(host=server_info.network_configuration.tls_server_name_indication)
        )

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

    # Parse and return each header
    return HttpHeadersScanResult(
        strict_transport_security_header=StrictTransportSecurityHeader.from_http_response(http_response),
        public_key_pins_header=PublicKeyPinsHeader.from_http_response(http_response),
        public_key_pins_report_only_header=PublicKeyPinsReportOnlyHeader.from_http_response(http_response),
        expect_ct_header=ExpectCtHeader.from_http_response(http_response),
    )


def _extract_first_header_value(response: HTTPResponse, header_name: str) -> Optional[str]:
    raw_header = response.getheader(header_name, None)
    if not raw_header:
        return None

    # Handle headers defined multiple times by picking the first value
    if "," in raw_header:
        raw_header = raw_header.split(",")[0]
    return raw_header


@dataclass(frozen=True)
class StrictTransportSecurityHeader:
    """A Strict-Transport-Security header parsed from a server's HTTP response.

    Attributes:
        preload: True if the preload directive is set.
        include_subdomains: True if the includesubdomains directive is set.
        max_age: The content of the max-age field.
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


@dataclass(frozen=True)
class PublicKeyPinsHeader:
    """A Public-Key-Pins header parsed from a server's HTTP response.

    Attributes:
        include_subdomains: True if the includesubdomains directive is set.
        max_age: The content of the max-age field.
        sha256_pins: The list of pin-sha256 values set in the header.
        report_uri: The content of the report-uri field.
        report_to: The content of the report-to field, available via the Reporting API as described at
            https://w3c.github.io/reporting/#examples.
    """

    max_age: Optional[int]
    sha256_pins: List[str]
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


@dataclass(frozen=True)
class PublicKeyPinsReportOnlyHeader(PublicKeyPinsHeader):
    """A Public-Key-Pins-Report-Only header parsed from a server's HTTP response.

    Attributes:
        include_subdomains: True if the includesubdomains directive is set.
        max_age: The content of the max-age field.
        sha256_pins: The list of pin-sha256 values set in the header.
        report_uri: The content of the report-uri field.
        report_to: The content of the report-to field, available via the Reporting API as described at
            https://w3c.github.io/reporting/#examples.
    """

    @classmethod
    def from_http_response(cls: Type[_T], response: HTTPResponse) -> Optional[_T]:
        raw_hpkp_report_only_header = _extract_first_header_value(response, "public-key-pins-report-only")
        if not raw_hpkp_report_only_header:
            return None
        return cls._from_header(raw_hpkp_report_only_header)


@dataclass(frozen=True)
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


# TODO
class CliConnector:

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
