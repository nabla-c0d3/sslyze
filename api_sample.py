from pathlib import Path

from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerConnectivityTester,
    Scanner,
    ServerScanRequest,
    ScanCommand,
    SslyzeOutputAsJson,
)
from sslyze.errors import ConnectionToServerFailed


def main() -> None:
    # First validate that we can connect to the servers we want to scan
    servers_to_scan = []
    for hostname in ["cloudflare.com", "google.com"]:
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(hostname, 443)
        try:
            server_info = ServerConnectivityTester().perform(server_location)
            servers_to_scan.append(server_info)
        except ConnectionToServerFailed as e:
            print(f"Error connecting to {server_location.hostname}:{server_location.port}: {e.error_message}")
            return

    scanner = Scanner()

    # Then queue some scan commands for each server
    all_server_scans = [
        ServerScanRequest(
            server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES}
        )
        for server_info in servers_to_scan
    ]
    scanner.start_scans(all_server_scans)

    # Then retrieve the result of the scan commands for each server
    for server_scan_result in scanner.get_results():
        print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

        # Scan commands that were run with no errors
        ssl2_result = server_scan_result.scan_commands_results.ssl_2_0_cipher_suites
        if ssl2_result:
            print("\nAccepted cipher suites for SSL 2.0:")
            for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
                print(f"* {accepted_cipher_suite.cipher_suite.name}")

        certinfo_result = server_scan_result.scan_commands_results.certificate_info
        if certinfo_result:
            print("\nCertificate info:")
            for cert_deployment in certinfo_result.certificate_deployments:
                print(f"Leaf certificate: \n{cert_deployment.received_certificate_chain_as_pem[0]}")

        # Scan commands that were run with errors
        for scan_command_error in server_scan_result.scan_commands_errors:
            print(f"\nError when running {scan_command_error.scan_command}:\n{scan_command_error.exception_trace}")


def basic_example_connectivity_testing() -> None:
    # Define the server that you want to scan
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)

    # Do connectivity testing to ensure SSLyze is able to connect
    try:
        server_info = ServerConnectivityTester().perform(server_location)
    except ConnectionToServerFailed as e:
        # Could not connect to the server; abort
        print(f"Error connecting to {server_location}: {e.error_message}")
        return
    print(f"Connectivity testing completed: {server_info}")


def basic_example() -> None:
    # Define the server that you want to scan
    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)

    # Do connectivity testing to ensure SSLyze is able to connect
    try:
        server_info = ServerConnectivityTester().perform(server_location)
    except ConnectionToServerFailed as e:
        # Could not connect to the server; abort
        print(f"Error connecting to {server_location}: {e.error_message}")
        return

    # Then queue some scan commands for the server
    scanner = Scanner()
    server_scan_req = ServerScanRequest(
        server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES},
    )
    scanner.start_scans([server_scan_req])

    # Then retrieve the results
    for server_scan_result in scanner.get_results():
        print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

        # SSL 2.0 results
        ssl2_result = server_scan_result.scan_commands_results.ssl_2_0_cipher_suites
        if ssl2_result:
            print("\nAccepted cipher suites for SSL 2.0:")
            for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
                print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # Certificate info results
        certinfo_result = server_scan_result.scan_commands_results.certificate_info
        if certinfo_result:
            print("\nCertificate info:")
            for cert_deployment in certinfo_result.certificate_deployments:
                print(f"Leaf certificate: \n{cert_deployment.received_certificate_chain_as_pem[0]}")


def example_json_result_parsing() -> None:
    # SSLyze scan results serialized to JSON were saved to this file using --json_out
    results_as_json_file = Path(__file__).parent / "tests" / "cli_tests" / "sslyze_output.json"
    results_as_json = results_as_json_file.read_text()

    # These results can be parsed
    parsed_results = SslyzeOutputAsJson.parse_raw(results_as_json)

    # Making it easy to do post-processing and inspection of the results
    print("The following servers were scanned:")
    for server_scan_result in parsed_results.server_scan_results:
        print(f"  {server_scan_result.server_info.server_location}")

        certinfo_result = server_scan_result.scan_commands_results.certificate_info
        if not certinfo_result:
            raise RuntimeError("Should never happen")
        for cert_deployment in certinfo_result.certificate_deployments:
            print(f"    SHA1 of leaf certificate: {cert_deployment.received_certificate_chain[0].fingerprint_sha1}")
        print("")


if __name__ == "__main__":
    main()
