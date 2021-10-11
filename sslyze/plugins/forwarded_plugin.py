from dataclasses import dataclass
from http.client import HTTPResponse
import logging

from nassl._nassl import SslError
from nassl.legacy_ssl_client import LegacySslClient
from nassl.ssl_client import ClientCertificateRequested

from sslyze.plugins.plugin_base import (
    ScanCommandResult,
    ScanCommandImplementation,
    ScanJob,
    ScanCommandExtraArguments,
    ScanCommandWrongUsageError,
    ScanCommandCliConnector,
    ScanJobResult,
)
from typing import List, Optional
from traceback import TracebackException

from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum
from sslyze.errors import ServerRejectedTlsHandshake
from sslyze.connection_helpers.http_request_generator import HttpRequestGenerator
from sslyze.connection_helpers.http_response_parser import HttpResponseParser, NotAValidHttpResponseError

_logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class ForwardedDetailedScanResult(ScanCommandResult):
    """The result of testing a server Forwarded header. See https://datatracker.ietf.org/doc/html/rfc7239

    Attributes:
        forwarded_by: The interface where the request came in to the proxy server.
        forwarded_for: The client that initiated the request and subsequent proxies in a chain of proxies.
        forwarded_host: The original value of the "Host" header field.
        forwarded_proto: The used protocol type. 
    """
    forwarded_by: List[str]
    forwarded_for: List[str]
    forwarded_host: List[str]
    forwarded_proto: List[str]

@dataclass(frozen=True)
class ForwardedScanResult(ScanCommandResult):
    """The result of testing a server Forwarded header.

    Attributes:
        http_request_sent: The initial HTTP request sent to the server by SSLyze.
        http_error_trace: An error the server returned after receiving the initial HTTP request. If this field is set,
            all the subsequent fields will be ``None`` as SSLyze did not receive a valid HTTP response from the server.
        http_path_redirected_to: The path SSLyze was eventually redirected to after sending the initial HTTP request.
        forwarded: The content of the worwarded header. As described at https://datatracker.ietf.org/doc/html/rfc7239
    """

    http_request_sent: str
    http_error_trace: Optional[TracebackException]
    http_path_redirected_to: Optional[str]

    forwarded: Optional[ForwardedDetailedScanResult]

class _ForwardedHeaderCliConnector(ScanCommandCliConnector[ForwardedScanResult, None]):

    _cli_option = "forwarded_header"
    _cli_description = "Test a server for the presence of security-related HTTP headers."

    @classmethod
    def result_to_console_output(cls, result: ForwardedScanResult) -> List[str]:
        result_as_txt = [cls._format_title("HTTP Forwarded Headers")]

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

        # Forwarded header
        result_as_txt.append(cls._format_subtitle("Forwarded Header"))
        if not result.forwarded:
            result_as_txt.append(cls._format_field("NOT SUPPORTED - Server did not return the header", ""))
        else:
            result_as_txt.append(cls._format_field("Forwarded By:", str(result.forwarded.forwarded_by)))
            result_as_txt.append(cls._format_field("Forwarded For:", str(result.forwarded.forwarded_for)))
            result_as_txt.append(cls._format_field("Forwarded Host:", str(result.forwarded.forwarded_host)))
            result_as_txt.append(cls._format_field("Forwarded Proto:", str(result.forwarded.forwarded_proto)))

        return result_as_txt


class ForwardedImplementation(ScanCommandImplementation[ForwardedScanResult, None]):
    """Test a server for HTTP headers related to security, including HSTS and HPKP.
    """

    cli_connector_cls = _ForwardedHeaderCliConnector

    @classmethod
    def scan_jobs_for_scan_command(
        cls, server_info: ServerConnectivityInfo, extra_arguments: Optional[ScanCommandExtraArguments] = None
    ) -> List[ScanJob]:
        if extra_arguments:
            raise ScanCommandWrongUsageError("This plugin does not take extra arguments")

        if server_info.network_configuration.tls_opportunistic_encryption:
            raise ScanCommandWrongUsageError("Cannot scan for Forwarded HTTP header against a non-HTTP server.")

        return [ScanJob(function_to_call=_retrieve_and_analyze_http_response, function_arguments=[server_info])]

    @classmethod
    def result_for_completed_scan_jobs(
        cls, server_info: ServerConnectivityInfo, scan_job_results: List[ScanJobResult]
    ) -> ForwardedScanResult:
        if len(scan_job_results) != 1:
            raise RuntimeError(f"Unexpected number of scan jobs received: {scan_job_results}")

        return scan_job_results[0].get_result()

def _retrieve_and_analyze_http_response(server_info: ServerConnectivityInfo) -> ForwardedScanResult:
    # Send HTTP requests until we no longer received an HTTP redirection, but allow only 4 redirections max
    _logger.info(f"Retrieving Forwarded HTTP header from {server_info}")
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
        return ForwardedScanResult(
            http_request_sent=initial_http_request,
            http_path_redirected_to=None,
            http_error_trace=http_error_trace,
            forwarded=None,
        )
    else:
        # If no HTTP error happened, parse and return each header
        return ForwardedScanResult(
            http_request_sent=initial_http_request,
            http_path_redirected_to=http_path_redirected_to,
            http_error_trace=None,
            forwarded=_parse_forwarded_header_from_http_response(http_response),
        )

def _extract_first_header_value(response: HTTPResponse, header_name: str) -> Optional[str]:
    raw_header = response.getheader(header_name, None)
    if not raw_header:
        return None

    # Handle headers defined multiple times by picking the first value
    if "," in raw_header:
        raw_header = raw_header.split(",")[0]
    return raw_header

def _parse_forwarded_header_from_http_response(response: HTTPResponse) -> Optional[ForwardedDetailedScanResult]:
    forwarded_header = _extract_first_header_value(response, "Forwarded")
    if not forwarded_header:
        return None

    result = ForwardedDetailedScanResult(
        forwarded_by=[],
        forwarded_for=[],
        forwarded_host=[],
        forwarded_proto=[],
    )

    pairs = forwarded_header.split(";")
    for pair in pairs:
        (key, value) = pair.split("=", 1)
        key = key.strip().lower()
        value = value.strip().strip("\"") # Want to preserve spaces inside quotes

        if "by" == key:
            result.forwarded_by.append(value)
        elif "for" == key:
            result.forwarded_for.append(value)
        elif "host" == key:
            result.forwarded_host.append(value)
        elif "proto" == key:
            result.forwarded_proto.append(value)
        else:
            _logger.warn("Unknown forwarded key '%s', with value '%s'" % (key, value))

    return result

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

