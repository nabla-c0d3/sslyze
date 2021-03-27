"""Script designed to scan a server running on localhost:443.

This is used in CI to ensure SSLyze is able to scan specific web servers (Apache2, IIS, etc.) running on localhost:443
with client authentication required.
.
See ./.github/workflows and https://github.com/nabla-c0d3/sslyze/issues/472 for more details.

$ PYTHONPATH=. python tests/web_servers/scan_localhost.py apache2
"""
import json
import sys
from dataclasses import asdict
from enum import Enum

from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerConnectivityTester,
    Scanner,
    ServerScanRequest,
    ClientAuthRequirementEnum,
    ScanCommandErrorReasonEnum,
    JsonEncoder,
)
from sslyze.cli.json_output import _SslyzeOutputAsJson
from sslyze.plugins.scan_commands import ScanCommandsRepository, ScanCommand


class WebServerSoftwareEnum(str, Enum):
    # There are small differences in the scan results of each supported server so the script needs to know
    # which type of server is being scanned
    APACHE2 = "apache2"
    NGINX = "nginx"
    IIS = "iis"


def main(server_software_running_on_localhost: WebServerSoftwareEnum) -> None:
    # Ensure the server is accessible on localhost
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("localhost", 443)
    server_info = ServerConnectivityTester().perform(server_location)

    if server_software_running_on_localhost == WebServerSoftwareEnum.APACHE2:
        # Apache2 is configured to require a client cert, and returns an error at the TLS layer if it is missing
        if server_info.tls_probing_result.client_auth_requirement != ClientAuthRequirementEnum.REQUIRED:
            raise RuntimeError(
                f"SSLyze did not detect that client authentication was required by Apache2:"
                f" {server_info.tls_probing_result.client_auth_requirement}."
            )
    elif server_software_running_on_localhost == WebServerSoftwareEnum.NGINX:
        # Nginx is configured to require a client cert but implements this by returning an error at the HTTP layer,
        # if the client cert is missing. This gets translated in SSLyze as "optionally" requiring a client cert
        if server_info.tls_probing_result.client_auth_requirement != ClientAuthRequirementEnum.OPTIONAL:
            raise RuntimeError(
                f"SSLyze did not detect that client authentication was required by Nginx:"
                f" {server_info.tls_probing_result.client_auth_requirement}."
            )
    elif server_software_running_on_localhost == WebServerSoftwareEnum.IIS:
        # IIS is not configured to require a client cert for now because I don't know how to enable this
        if server_info.tls_probing_result.client_auth_requirement != ClientAuthRequirementEnum.DISABLED:
            raise RuntimeError(
                f"SSLyze detected that client authentication was enabled by IIS:"
                f" {server_info.tls_probing_result.client_auth_requirement}."
            )
    else:
        raise ValueError(f"Unexpected value: {server_software_running_on_localhost}")

    # Queue all scan commands
    print("Starting scan.")
    scanner = Scanner()
    server_scan_req = ServerScanRequest(
        server_info=server_info, scan_commands=ScanCommandsRepository.get_all_scan_commands(),
    )
    scanner.start_scans([server_scan_req])

    # Retrieve the result
    for server_scan_result in scanner.get_results():
        successful_cmds_count = len(server_scan_result.scan_commands_results)
        errored_cmds_count = len(server_scan_result.scan_commands_errors)
        print(f"Finished scan with {successful_cmds_count} results and {errored_cmds_count} errors.")

        # Crash if any scan commands triggered an error that's not due to client authentication being required
        triggered_unexpected_error = False
        for scan_command, error in server_scan_result.scan_commands_errors.items():
            if error.reason != ScanCommandErrorReasonEnum.CLIENT_CERTIFICATE_NEEDED:
                triggered_unexpected_error = True
                print(f"\nError when running {scan_command}: {error.reason.name}.")
                if error.exception_trace:
                    exc_trace = ""
                    for line in error.exception_trace.format(chain=False):
                        exc_trace += f"       {line}"
                    print(exc_trace)

                print("\n")

        if triggered_unexpected_error:
            raise RuntimeError("The scan triggered unexpected errors")
        else:
            # The CLIENT_CERTIFICATE_NEEDED errors are expected, because of how Apache2 is configured
            print("OK: Triggered CLIENT_CERTIFICATE_NEEDED errors only.")

        # Crash if SSLyze didn't complete the scan commands that are supposed to work even when we don't provide a
        # client certificate
        if server_software_running_on_localhost == WebServerSoftwareEnum.APACHE2:
            expected_scan_command_results = {
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.HEARTBLEED,
                ScanCommand.ELLIPTIC_CURVES,
                ScanCommand.TLS_FALLBACK_SCSV,
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_COMPRESSION,
            }
        elif server_software_running_on_localhost == WebServerSoftwareEnum.NGINX:
            # With nginx, when configured to require client authentication, more scan commands work because unlike
            # Apache2, it does complete a full TLS handshake even when a client cert was not provided. It then returns
            # an error page at the HTTP layer.
            expected_scan_command_results = {
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.HEARTBLEED,
                ScanCommand.ELLIPTIC_CURVES,
                ScanCommand.TLS_FALLBACK_SCSV,
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.TLS_COMPRESSION,
                ScanCommand.SESSION_RESUMPTION,
                ScanCommand.TLS_1_3_EARLY_DATA,
                ScanCommand.HTTP_HEADERS,
                ScanCommand.SESSION_RESUMPTION_RATE,
                ScanCommand.SESSION_RENEGOTIATION,
            }
        elif server_software_running_on_localhost == WebServerSoftwareEnum.IIS:
            # With IIS, client authentication is not enabled so all scan commands should succeed
            expected_scan_command_results = ScanCommandsRepository.get_all_scan_commands()  # type: ignore
        else:
            raise ValueError(f"Unexpected value: {server_software_running_on_localhost}")

        completed_scan_command_results = server_scan_result.scan_commands_results.keys()
        if completed_scan_command_results != expected_scan_command_results:
            raise RuntimeError(
                f"SSLyze did not complete all the expected scan commands: {completed_scan_command_results}"
            )
        else:
            print("OK: Completed all the expected scan commands.")

        # Ensure the right TLS versions were detected by SSLyze as enabled
        # https://github.com/nabla-c0d3/sslyze/issues/472
        if server_software_running_on_localhost in [WebServerSoftwareEnum.APACHE2, WebServerSoftwareEnum.NGINX]:
            # Apache and nginx are configured to only enable TLS 1.2 and TLS 1.3
            expected_enabled_tls_scan_commands = {
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
            }
        elif server_software_running_on_localhost == WebServerSoftwareEnum.IIS:
            # TLS 1.3 is not supported by IIS
            expected_enabled_tls_scan_commands = {
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
            }
        else:
            raise ValueError(f"Unexpected value: {server_software_running_on_localhost}")

        for ciphers_scan_cmd in expected_enabled_tls_scan_commands:
            scan_cmd_result = server_scan_result.scan_commands_results[ciphers_scan_cmd]  # type: ignore
            if not scan_cmd_result.accepted_cipher_suites:
                raise RuntimeError(
                    f"SSLyze did not detect {scan_cmd_result.tls_version_used.name} to be enabled on the server."
                )
            else:
                print(f"OK: Scan command {ciphers_scan_cmd} detected cipher suites.")

        # Ensure a JSON output can be generated from the results
        json_output = _SslyzeOutputAsJson(
            server_scan_results=[server_scan_result], server_connectivity_errors=[], total_scan_time=3,
        )
        json_output_as_dict = asdict(json_output)
        json.dumps(json_output_as_dict, cls=JsonEncoder, sort_keys=True, indent=4, ensure_ascii=True)
        print("OK: Was able to generate JSON output.")


if __name__ == "__main__":
    server_argument = WebServerSoftwareEnum(sys.argv[1])
    main(server_argument)
