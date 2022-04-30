import logging
from http.client import HTTPResponse

from dataclasses import dataclass, asdict
from traceback import TracebackException
from urllib.parse import urlsplit

import pydantic
from nassl._nassl import SslError

from sslyze.json.scan_attempt_json import ScanCommandAttemptAsJson
from sslyze.plugins.plugin_base import (
    ScanCommandImplementation,
    ScanCommandExtraArgument,
    ScanJob,
    ScanCommandResult,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
    ScanJobResult,
)
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.connection_helpers.http_request_generator import HttpRequestGenerator
from sslyze.connection_helpers.http_response_parser import HttpResponseParser, NotAValidHttpResponseError
from typing import List, Optional


_logger = logging.getLogger(__name__)


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

    Each HTTP header described below will be ``None`` if the server did not return a valid HTTP response, or if the
    server returned an HTTP response without the HTTP header.

    Attributes:
        http_request_sent: The initial HTTP request sent to the server by SSLyze.
        http_error_trace: An error the server returned after receiving the initial HTTP request. If this field is set,
            all the subsequent fields will be ``None`` as SSLyze did not receive a valid HTTP response from the server.
        http_path_redirected_to: The path SSLyze was eventually redirected to after sending the initial HTTP request.
        strict_transport_security_header: The Strict-Transport-Security header returned by the server.
        expect_ct_header: The Expect-CT header returned by the server.
    """

    http_request_sent: str
    http_error_trace: Optional[TracebackException]

    http_path_redirected_to: Optional[str]
    strict_transport_security_header: Optional[StrictTransportSecurityHeader]
    expect_ct_header: Optional[ExpectCtHeader]


class _ExpectCtHeaderAsJson(pydantic.BaseModel):
    max_age: Optional[int]
    report_uri: Optional[str]
    enforce: bool


_ExpectCtHeaderAsJson.__doc__ = ExpectCtHeader.__doc__  # type: ignore


class _StrictTransportSecurityHeaderAsJson(pydantic.BaseModel):
    max_age: Optional[int]
    preload: bool
    include_subdomains: bool


_StrictTransportSecurityHeaderAsJson.__doc__ = StrictTransportSecurityHeader.__doc__  # type: ignore


class HttpHeadersScanResultAsJson(pydantic.BaseModel):
    http_request_sent: str
    http_error_trace: Optional[str]

    http_path_redirected_to: Optional[str]
    strict_transport_security_header: Optional[_StrictTransportSecurityHeaderAsJson]
    expect_ct_header: Optional[_ExpectCtHeaderAsJson]

    class Config:
        orm_mode = True

    @classmethod
    def from_orm(cls, result: HttpHeadersScanResult) -> "HttpHeadersScanResultAsJson":
        http_error_trace_as_str = None
        if result.http_error_trace:
            http_error_trace_as_str = ""
            for line in result.http_error_trace.format(chain=False):
                http_error_trace_as_str += line

        sts_header_json = None
        if result.strict_transport_security_header:
            sts_header_json = _StrictTransportSecurityHeaderAsJson(**asdict(result.strict_transport_security_header))

        ct_header_json = None
        if result.expect_ct_header:
            ct_header_json = _ExpectCtHeaderAsJson(**asdict(result.expect_ct_header))

        return cls(
            http_request_sent=result.http_request_sent,
            http_error_trace=http_error_trace_as_str,
            http_path_redirected_to=result.http_path_redirected_to,
            strict_transport_security_header=sts_header_json,
            expect_ct_header=ct_header_json,
        )


HttpHeadersScanResultAsJson.__doc__ = HttpHeadersScanResult.__doc__  # type: ignore


class HttpHeadersScanAttemptAsJson(ScanCommandAttemptAsJson):
    result: Optional[HttpHeadersScanResultAsJson]


class _HttpHeadersCliConnector(ScanCommandCliConnector[HttpHeadersScanResult, None]):

    _cli_option = "http_headers"
    _cli_description = "Test a server for the presence of security-related HTTP headers."

    @classmethod
    def result_to_console_output(cls, result: HttpHeadersScanResult) -> List[str]:
        result_as_txt = [cls._format_title("HTTP Security Headers")]

        # If an error occurred after sending the HTTP request, just display it
        if result.http_error_trace:
            result_as_txt.append(
                cls._format_subtitle("Error: The server did not return a valid HTTP response. Is it an HTTP server?")
            )
            # Extract the last line which contains the reason
            last_line = None
            for line in result.http_error_trace.format(chain=False):
                last_line = line
            if last_line:
                result_as_txt.append(f"     Error details: {last_line.strip()}")

            return result_as_txt

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
    """Test a server for HTTP headers related to security, including HSTS and HPKP."""

    cli_connector_cls = _HttpHeadersCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArgument] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        if server_info.network_configuration.tls_opportunistic_encryption:
            raise ScanCommandWrongUsageError("Cannot scan for HTTP headers against a non-HTTP server.")

        return [ScanJob(function_to_call=_retrieve_and_analyze_http_response, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> HttpHeadersScanResult:
        if len(scan_job_results) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        return scan_job_results[0].get_result()


def _retrieve_and_analyze_http_response(server_info: ServerConnectivityInfo) -> HttpHeadersScanResult:
    # Send HTTP requests until we no longer received an HTTP redirection, but allow only 4 redirections max
    _logger.info(f"Retrieving HTTP headers from {server_info}")
    redirections_count = 0
    next_location_path: Optional[str] = "/"
    http_error_trace = None

    while next_location_path and redirections_count < 4:
        _logger.info(f"Sending HTTP request to {next_location_path}")
        http_path_redirected_to = next_location_path

        # Perform the TLS handshake
        ssl_connection = server_info.get_preconfigured_tls_connection()
        ssl_connection.connect()

        try:
            # Send an HTTP GET request to the server
            ssl_connection.ssl_client.write(
                HttpRequestGenerator.get_request(
                    host=server_info.network_configuration.tls_server_name_indication, path=next_location_path
                )
            )
            http_response = HttpResponseParser.parse_from_ssl_connection(ssl_connection.ssl_client)

        except (OSError, NotAValidHttpResponseError, SslError) as e:
            # The server closed/rejected the connection, or didn't return a valid HTTP response
            http_error_trace = TracebackException.from_exception(e)

        finally:
            ssl_connection.close()

        if http_error_trace:
            break

        # Handle redirection if there is one
        next_location_path = _detect_http_redirection(
            http_response=http_response,
            server_host_name=server_info.network_configuration.tls_server_name_indication,
            server_port=server_info.server_location.port,
        )
        redirections_count += 1

    # Prepare the results
    initial_http_request = HttpRequestGenerator.get_request(
        host=server_info.network_configuration.tls_server_name_indication, path="/"
    ).decode("ascii")

    if http_error_trace:
        # If the server errored when receiving an HTTP request, return the error as the result
        return HttpHeadersScanResult(
            http_request_sent=initial_http_request,
            http_error_trace=http_error_trace,
            http_path_redirected_to=None,
            strict_transport_security_header=None,
            expect_ct_header=None,
        )
    else:
        # If no HTTP error happened, parse and return each header
        return HttpHeadersScanResult(
            http_request_sent=initial_http_request,
            http_path_redirected_to=http_path_redirected_to,
            http_error_trace=None,
            strict_transport_security_header=_parse_hsts_header_from_http_response(http_response),
            expect_ct_header=_parse_expect_ct_header_from_http_response(http_response),
        )


def _detect_http_redirection(http_response: HTTPResponse, server_host_name: str, server_port: int) -> Optional[str]:
    """If the HTTP response contains a redirection to the same server, return the path to the new location."""
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
            _logger.warning(f"Unexpected value in HSTS header: {repr(hsts_directive)}")

    return StrictTransportSecurityHeader(max_age, preload, include_subdomains)


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
            _logger.warning(f"Unexpected value in Expect-CT header: {repr(expect_ct_directive)}")

    return ExpectCtHeader(max_age, report_uri, enforce)
