from concurrent.futures._base import Future
from http.client import HTTPResponse

from dataclasses import dataclass
from urllib.parse import urlsplit

from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandExtraArguments,
    ScanJob,
    ScanCommandResult,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
)
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.connection_helpers.http_request_generator import HttpRequestGenerator
from sslyze.connection_helpers.http_response_parser import HttpResponseParser
from typing import List, Optional


@dataclass(frozen=True)
class PublicKeyPinsHeader:
    """A Public-Key-Pins header parsed from a server's HTTP response.

    Attributes:
        include_subdomains: ``True`` if the includesubdomains directive is set.
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


@dataclass(frozen=True)
class ExpectCtHeader:
    """An Expect-CT header parsed from a server's HTTP response.

    Attributes:
        max-age: The content of the max-age field.
        report-uri: The content of report-uri field.
        enforce: True if enforce directive is set.
    """

    max_age: Optional[int]
    report_uri: Optional[str]
    enforce: bool


@dataclass(frozen=True)
class StrictTransportSecurityHeader:
    """A Strict-Transport-Security header parsed from a server's HTTP response.

    Attributes:
        preload: ``True`` if the preload directive is set.
        include_subdomains: ``True`` if the includesubdomains directive is set.
        max_age: The content of the max-age field.
    """

    max_age: Optional[int]
    preload: bool
    include_subdomains: bool


@dataclass(frozen=True)
class HttpHeadersScanResult(ScanCommandResult):
    """The result of testing a server for the presence of security-related HTTP headers.

    Each HTTP header described below will be ``None`` if the server did not return it.

    Attributes:
        strict_transport_security_header: The Strict-Transport-Security header returned by the server.
        public_key_pins_header: The Public-Key-Pins header returned by the server.
        public_key_pins_report_only_header: The Public-Key-Pins-Report-Only header returned by the server.
        expect_ct_header: The Expect-CT header returned by the server.
    """

    strict_transport_security_header: Optional[StrictTransportSecurityHeader]

    public_key_pins_header: Optional[PublicKeyPinsHeader]
    public_key_pins_report_only_header: Optional[PublicKeyPinsHeader]

    expect_ct_header: Optional[ExpectCtHeader]


class _HttpHeadersCliConnector(ScanCommandCliConnector[HttpHeadersScanResult, None]):

    _cli_option = "http_headers"
    _cli_description = "Test a server for the presence of security-related HTTP headers."

    @classmethod
    def result_to_console_output(cls, result: HttpHeadersScanResult) -> List[str]:
        result_as_txt = [cls._format_title("HTTP Security Headers")]

        # HSTS
        result_as_txt.append(cls._format_subtitle("Strict-Transport-Security Header"))
        if not result.strict_transport_security_header:
            result_as_txt.append(cls._format_field("NOT SUPPORTED - Server did not return the header", ""))
        else:
            result_as_txt.append(cls._format_field("Max Age:", str(result.strict_transport_security_header.max_age)))
            result_as_txt.append(
                cls._format_field(
                    "Include Subdomains:", str(result.strict_transport_security_header.include_subdomains)
                )
            )
            result_as_txt.append(cls._format_field("Preload:", str(result.strict_transport_security_header.preload)))

        # HPKP
        for header, subtitle in [
            (result.public_key_pins_header, "Public-Key-Pins Header"),
            (result.public_key_pins_report_only_header, "Public-Key-Pins-Report-Only Header"),
        ]:
            result_as_txt.extend(["", cls._format_subtitle(subtitle)])
            if not header:
                result_as_txt.append(cls._format_field("NOT SUPPORTED - Server did not return the header", ""))
            else:
                result_as_txt.append(cls._format_field("Max Age:", str(header.max_age)))
                result_as_txt.append(cls._format_field("Include Subdomains:", str(header.include_subdomains)))
                result_as_txt.append(cls._format_field("Report URI:", str(header.report_uri)))
                result_as_txt.append(cls._format_field("SHA-256 Pin List:", ", ".join(header.sha256_pins)))

        # Expect-CT
        result_as_txt.extend(["", cls._format_subtitle("Expect-CT Header")])
        if not result.expect_ct_header:
            result_as_txt.append(cls._format_field("NOT SUPPORTED - Server did not return the header", ""))
        else:
            result_as_txt.append(cls._format_field("Max Age:", str(result.expect_ct_header.max_age)))
            result_as_txt.append(cls._format_field("Report- URI:", str(result.expect_ct_header.report_uri)))
            result_as_txt.append(cls._format_field("Enforce:", str(result.expect_ct_header.enforce)))

        return result_as_txt


class HttpHeadersImplementation(ScanCommandImplementation[HttpHeadersScanResult, None]):
    """Test a server for HTTP headers related to security, including HSTS and HPKP.
    """

    cli_connector_cls = _HttpHeadersCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        if server_info.network_configuration.tls_opportunistic_encryption:
            raise ScanCommandWrongUsageError("Cannot test for HTTP headers on a StartTLS connection.")

        return [ScanJob(function_to_call=_retrieve_and_analyze_http_response, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, completed_scan_jobs: List[Future]
    ) -> HttpHeadersScanResult:
        if len(completed_scan_jobs) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {completed_scan_jobs}")

        return completed_scan_jobs[0].result()


def _retrieve_and_analyze_http_response(server_info: ServerConnectivityInfo) -> HttpHeadersScanResult:
    # Send HTTP requests until we no longer received an HTTP redirection, but allow only 4 redirections max
    redirections_count = 0
    next_location_path: Optional[str] = "/"
    while next_location_path and redirections_count < 4:
        ssl_connection = server_info.get_preconfigured_tls_connection()
        try:
            # Perform the TLS handshake
            ssl_connection.connect()

            # Send an HTTP GET request to the server
            ssl_connection.ssl_client.write(
                HttpRequestGenerator.get_request(
                    host=server_info.network_configuration.tls_server_name_indication, path=next_location_path
                )
            )
            http_response = HttpResponseParser.parse_from_ssl_connection(ssl_connection.ssl_client)
        finally:
            ssl_connection.close()

        if http_response.version == 9:
            # HTTP 0.9 => Probably not an HTTP response
            raise ValueError("Server did not return an HTTP response")

        # Handle redirection if there is one
        next_location_path = _detect_http_redirection(
            http_response=http_response,
            server_host_name=server_info.network_configuration.tls_server_name_indication,
            server_port=server_info.server_location.port,
        )
        redirections_count += 1

    # Parse and return each header
    return HttpHeadersScanResult(
        strict_transport_security_header=_parse_hsts_header_from_http_response(http_response),
        public_key_pins_header=_parse_hpkp_header_from_http_response(http_response),
        public_key_pins_report_only_header=_parse_hpkp_report_only_header_from_http_response(http_response),
        expect_ct_header=_parse_expect_ct_header_from_http_response(http_response),
    )


def _detect_http_redirection(http_response: HTTPResponse, server_host_name: str, server_port: int) -> Optional[str]:
    """If the HTTP response contains a redirection to the same server, return the path to the new location.
    """
    next_location_path = None
    if 300 <= http_response.status < 400:
        location_header = _extract_first_header_value(http_response, "Location")
        if location_header:
            parsed_location = urlsplit(location_header)
            is_relative_url = False if parsed_location.hostname else True
            if is_relative_url:
                # Yes, to a relative URL; follow the redirection
                next_location_path = location_header
            else:
                is_absolute_url_to_same_hostname = parsed_location.hostname == server_host_name
                absolute_url_port = 443 if parsed_location.port is None else parsed_location.port
                is_absolute_url_to_same_port = absolute_url_port == server_port
                if is_absolute_url_to_same_hostname and is_absolute_url_to_same_port:
                    # Yes, to an absolute URL to the same server; follow the redirection
                    next_location_path = f"{parsed_location.path}"
                    if parsed_location.query:
                        next_location_path += f"?{parsed_location.query}"

    return next_location_path


def _extract_first_header_value(response: HTTPResponse, header_name: str) -> Optional[str]:
    raw_header = response.getheader(header_name, None)
    if not raw_header:
        return None

    # Handle headers defined multiple times by picking the first value
    if "," in raw_header:
        raw_header = raw_header.split(",")[0]
    return raw_header


def _parse_hsts_header_from_http_response(response: HTTPResponse) -> Optional[StrictTransportSecurityHeader]:
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

    return StrictTransportSecurityHeader(max_age, preload, include_subdomains)


def _parse_hpkp_report_only_header_from_http_response(response: HTTPResponse) -> Optional[PublicKeyPinsHeader]:
    raw_hpkp_report_only_header = _extract_first_header_value(response, "public-key-pins-report-only")
    if not raw_hpkp_report_only_header:
        return None
    return _parse_hpkp_from_header(raw_hpkp_report_only_header)


def _parse_hpkp_header_from_http_response(response: HTTPResponse) -> Optional[PublicKeyPinsHeader]:
    raw_hpkp_header = _extract_first_header_value(response, "public-key-pins")
    if not raw_hpkp_header:
        return None
    return _parse_hpkp_from_header(raw_hpkp_header)


def _parse_hpkp_from_header(raw_hpkp_header: str) -> PublicKeyPinsHeader:
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

    return PublicKeyPinsHeader(max_age, pin_sha256_list, include_subdomains, report_uri, report_to)


def _parse_expect_ct_header_from_http_response(response: HTTPResponse) -> Optional[ExpectCtHeader]:
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

    return ExpectCtHeader(max_age, report_uri, enforce)
