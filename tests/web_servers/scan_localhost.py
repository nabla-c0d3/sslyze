"""Script designed to scan a server running on localhost:443.

This is used in CI to ensure SSLyze is able to scan specific web servers (Apache2, IIS, etc.) running on localhost:443
with client authentication required.
.
See ./.github/workflows and https://github.com/nabla-c0d3/sslyze/issues/472 for more details.

$ PYTHONPATH=. python tests/web_servers/scan_localhost.py
"""

from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerConnectivityTester,
    Scanner,
    ServerScanRequest,
    ClientAuthRequirementEnum,
    CipherSuitesScanResult,
    ScanCommandErrorReasonEnum,
)
from sslyze.plugins.scan_commands import ScanCommandsRepository, ScanCommand


def main() -> None:
    # Ensure the server is accessible on localhost
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("localhost", 443)
    server_info = ServerConnectivityTester().perform(server_location)

    if server_info.tls_probing_result.client_auth_requirement != ClientAuthRequirementEnum.REQUIRED:
        raise RuntimeError(
            f"SSLyze did not detect that client authentication was required by the server:"
            f" {server_info.tls_probing_result.client_auth_requirement}."
        )

    # Queue all scan commands
    print("Starting scan.")
    scanner = Scanner()
    server_scan_req = ServerScanRequest(
        server_info=server_info, scan_commands=ScanCommandsRepository.get_all_scan_commands(),
    )
    scanner.queue_scan(server_scan_req)

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
        if server_scan_result.scan_commands_results.keys() != expected_scan_command_results:
            raise RuntimeError("SSLyze did not complete all the expected scan commands.")
        else:
            print("OK: Completed all the expected scan commands.")

        # Ensure TLS 1.2 and 1.3 were detected by SSLyze to be enabled
        # https://github.com/nabla-c0d3/sslyze/issues/472
        for ciphers_scan_cmd in [ScanCommand.TLS_1_3_CIPHER_SUITES, ScanCommand.TLS_1_2_CIPHER_SUITES]:
            scan_cmd_result = server_scan_result.scan_commands_results[ciphers_scan_cmd]  # type: ignore
            if not scan_cmd_result.accepted_cipher_suites:
                raise RuntimeError(
                    f"SSLyze did not detect {scan_cmd_result.tls_version_used.name} to be enabled on the server."
                )
            else:
                print(f"OK: Scan command {ciphers_scan_cmd} detected cipher suites.")


if __name__ == "__main__":
    main()
