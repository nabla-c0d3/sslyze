from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerConnectivityTester,
    Scanner,
    ServerScanRequest,
    ScanCommand,
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
    for server_info in servers_to_scan:
        server_scan_req = ServerScanRequest(
            server_info=server_info, scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES},
        )
        scanner.queue_scan(server_scan_req)

    # Then retrieve the result of the scan commands for each server
    for server_scan_result in scanner.get_results():
        print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

        # Scan commands that were run with no errors
        try:
            ssl2_result = server_scan_result.scan_commands_results[ScanCommand.SSL_2_0_CIPHER_SUITES]
            print("\nAccepted cipher suites for SSL 2.0:")
            for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
                print(f"* {accepted_cipher_suite.cipher_suite.name}")
        except KeyError:
            pass

        try:
            certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
            print("\nCertificate info:")
            for cert_deployment in certinfo_result.certificate_deployments:
                print(f"Leaf certificate: \n{cert_deployment.received_certificate_chain_as_pem[0]}")
        except KeyError:
            pass

        # Scan commands that were run with errors
        for scan_command, error in server_scan_result.scan_commands_errors.items():
            print(f"\nError when running {scan_command}:\n{error.exception_trace}")


if __name__ == "__main__":
    main()


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
    scanner.queue_scan(server_scan_req)

    # Then retrieve the results
    for server_scan_result in scanner.get_results():
        print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

        # SSL 2.0 results
        ssl2_result = server_scan_result.scan_commands_results[ScanCommand.SSL_2_0_CIPHER_SUITES]
        print("\nAccepted cipher suites for SSL 2.0:")
        for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
            print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # Certificate info results
        certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
        print("\nCertificate info:")
        for cert_deployment in certinfo_result.certificate_deployments:
            print(f"Leaf certificate: \n{cert_deployment.received_certificate_chain_as_pem[0]}")
