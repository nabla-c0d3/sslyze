from datetime import datetime
from pathlib import Path
from typing import List

from sslyze import (
    Scanner,
    ServerScanRequest,
    SslyzeOutputAsJson,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
    ServerScanResult,
    ServerScanResultAsJson,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt


def _print_failed_scan_command_attempt(scan_command_attempt: ScanCommandAttempt) -> None:
    print(
        f"\nError when running ssl_2_0_cipher_suites: {scan_command_attempt.error_reason}:\n"
        f"{scan_command_attempt.error_trace}"
    )


def main() -> None:
    print("=> Starting the scans")
    date_scans_started = datetime.utcnow()

    # First create the scan requests for each server that we want to scan
    try:
        all_scan_requests = [
            ServerScanRequest(server_location=ServerNetworkLocation(hostname="cloudflare.com")),
            ServerScanRequest(server_location=ServerNetworkLocation(hostname="google.com")),
        ]
    except ServerHostnameCouldNotBeResolved:
        # Handle bad input ie. invalid hostnames
        print("Error resolving the supplied hostnames")
        return

    # Then queue all the scans
    scanner = Scanner()
    scanner.queue_scans(all_scan_requests)

    # And retrieve and process the results for each server
    all_server_scan_results = []
    for server_scan_result in scanner.get_results():
        all_server_scan_results.append(server_scan_result)
        print(f"\n\n****Results for {server_scan_result.server_location.hostname}****")

        # Were we able to connect to the server and run the scan?
        if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            # No we weren't
            print(
                f"\nError: Could not connect to {server_scan_result.server_location.hostname}:"
                f" {server_scan_result.connectivity_error_trace}"
            )
            continue

        # Since we were able to run the scan, scan_result is populated
        assert server_scan_result.scan_result

        # Process the result of the SSL 2.0 scan command
        ssl2_attempt = server_scan_result.scan_result.ssl_2_0_cipher_suites
        if ssl2_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            # An error happened when this scan command was run
            _print_failed_scan_command_attempt(ssl2_attempt)
        elif ssl2_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            # This scan command was run successfully
            ssl2_result = ssl2_attempt.result
            assert ssl2_result
            print("\nAccepted cipher suites for SSL 2.0:")
            for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
                print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # Process the result of the TLS 1.3 scan command
        tls1_3_attempt = server_scan_result.scan_result.tls_1_3_cipher_suites
        if tls1_3_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            _print_failed_scan_command_attempt(ssl2_attempt)
        elif tls1_3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            tls1_3_result = tls1_3_attempt.result
            assert tls1_3_result
            print("\nAccepted cipher suites for TLS 1.3:")
            for accepted_cipher_suite in tls1_3_result.accepted_cipher_suites:
                print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # Process the result of the certificate info scan command
        certinfo_attempt = server_scan_result.scan_result.certificate_info
        if certinfo_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            _print_failed_scan_command_attempt(certinfo_attempt)
        elif certinfo_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            certinfo_result = certinfo_attempt.result
            assert certinfo_result
            print("\nLeaf certificates deployed:")
            for cert_deployment in certinfo_result.certificate_deployments:
                leaf_cert = cert_deployment.received_certificate_chain[0]
                print(
                    f"{leaf_cert.public_key().__class__.__name__}: {leaf_cert.subject.rfc4514_string()}"
                    f" (Serial: {leaf_cert.serial_number})"
                )

        # etc... Other scan command results to process are in server_scan_result.scan_result

    # Lastly, save the all the results to a JSON file
    json_file_out = Path(f"api_sample_results.json")
    print(f"\n\n=> Saving scan results to {json_file_out}")
    example_json_result_output(json_file_out, all_server_scan_results, date_scans_started, datetime.utcnow())

    # And ensure we are able to parse them
    print(f"\n\n=> Parsing scan results from {json_file_out}")
    example_json_result_parsing(json_file_out)


def example_json_result_output(
    json_file_out: Path,
    all_server_scan_results: List[ServerScanResult],
    date_scans_started: datetime,
    date_scans_completed: datetime,
) -> None:
    json_output = SslyzeOutputAsJson(
        server_scan_results=[ServerScanResultAsJson.from_orm(result) for result in all_server_scan_results],
        invalid_server_strings=[],  # Not needed here - specific to the CLI interface
        date_scans_started=date_scans_started,
        date_scans_completed=date_scans_completed,
    )
    json_output_as_str = json_output.json(sort_keys=True, indent=4, ensure_ascii=True)
    json_file_out.write_text(json_output_as_str)


def example_json_result_parsing(results_as_json_file: Path) -> None:
    # SSLyze scan results serialized to JSON were saved to this file using --json_out
    results_as_json = results_as_json_file.read_text()

    # These results can be parsed
    parsed_results = SslyzeOutputAsJson.parse_raw(results_as_json)

    # Making it easy to do post-processing and inspection of the results
    print("The following servers were scanned:")
    for server_scan_result in parsed_results.server_scan_results:
        print(f"\n****{server_scan_result.server_location.hostname}:{server_scan_result.server_location.port}****")

        if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print(f"That scan failed with the following error:\n{server_scan_result.connectivity_error_trace}")
            continue

        assert server_scan_result.scan_result
        certinfo_attempt = server_scan_result.scan_result.certificate_info
        if certinfo_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            _print_failed_scan_command_attempt(certinfo_attempt)  # type: ignore
        else:
            certinfo_result = server_scan_result.scan_result.certificate_info.result
            assert certinfo_result
            for cert_deployment in certinfo_result.certificate_deployments:
                print(f"    SHA1 of leaf certificate: {cert_deployment.received_certificate_chain[0].fingerprint_sha1}")
            print("")


if __name__ == "__main__":
    main()
