from typing import cast

from sslyze.connection_helpers.errors import ConnectionToServerFailed
from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.openssl_cipher_suites.implementation import CipherSuitesScanResult
from sslyze.plugins.scan_commands import ScanCommandEnum
from sslyze.scanner import ServerScanRequest, Scanner
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection


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
            server_info=server_info,
            scan_commands={
                ScanCommandEnum.TLS_1_0_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_1_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_2_CIPHER_SUITES,
                ScanCommandEnum.CERTIFICATE_INFO,
                ScanCommandEnum.TLS_COMPRESSION,
            },
        )
        scanner.queue_scan(server_scan_req)

    # Then retrieve the result of the scan commands for each server
    for server_scan_result in scanner.get_results():
        print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

        # Scan commands that were run with no errors
        for scan_command, result in server_scan_result.scan_commands_results.items():
            if scan_command in [
                ScanCommandEnum.TLS_1_0_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_1_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_2_CIPHER_SUITES,
            ]:
                typed_result = cast(CipherSuitesScanResult, result)
                print(f"\nAccepted cipher suites for {scan_command.name}:")
                for accepted_cipher_suite in typed_result.accepted_cipher_suites:
                    print(f"* {accepted_cipher_suite.cipher_suite.name}")

            elif scan_command == ScanCommandEnum.CERTIFICATE_INFO:
                typed_result = cast(CertificateInfoScanResult, result)
                print("\nCertificate info:")
                for cert_deployment in typed_result.certificate_deployments:
                    print(f"Leaf certificate: \n{cert_deployment.verified_certificate_chain_as_pem[0]}")

            elif scan_command == ScanCommandEnum.TLS_COMPRESSION:
                typed_result = cast(CompressionScanResult, result)
                print(f"\nCompression / CRIME: {typed_result.supports_compression}")

        # Scan commands that were run with errors
        for scan_command, error in server_scan_result.scan_commands_errors.items():
            print(f"\nError when running {scan_command}:\n{error.exception_trace}")


if __name__ == "__main__":
    main()
