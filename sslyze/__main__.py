import sys
from datetime import datetime, timezone
from typing import TextIO

from sslyze import (
    Scanner,
    ServerConnectivityStatusEnum,
    ServerScanRequest,
    ServerScanResultAsJson,
    SslyzeOutputAsJson,
)
from sslyze.__version__ import __version__
from sslyze.cli.command_line_parser import CommandLineParser, CommandLineParsingError
from sslyze.cli.console_output import ObserverToGenerateConsoleOutput
from sslyze.json.json_output import InvalidServerStringAsJson
from sslyze.mozilla_tls_profile.tls_config_checker import (
    ServerNotCompliantWithTlsConfiguration,
    ServerScanResultIncomplete,
    TlsConfigurationEnum,
    check_server_against_tls_configuration,
)


def main() -> None:
    # Parse the supplied command line
    date_scans_started = datetime.now(timezone.utc)
    sslyze_parser = CommandLineParser(__version__)
    try:
        parsed_command_line = sslyze_parser.parse_command_line()
    except CommandLineParsingError as e:
        print(e.get_error_msg())
        return

    # Setup the observer to print to the console, if needed
    scanner_observers = []
    if not parsed_command_line.should_disable_console_output:
        observer_for_console_output = ObserverToGenerateConsoleOutput(
            file_to=sys.stdout, json_path_out=parsed_command_line.json_path_out
        )
        observer_for_console_output.command_line_parsed(parsed_command_line=parsed_command_line)

        scanner_observers.append(observer_for_console_output)

    # Setup the scanner
    sslyze_scanner = Scanner(
        per_server_concurrent_connections_limit=parsed_command_line.per_server_concurrent_connections_limit,
        concurrent_server_scans_limit=parsed_command_line.concurrent_server_scans_limit,
        observers=scanner_observers,
    )

    # Queue the scans
    all_server_scan_requests = []
    for server_location, network_config in parsed_command_line.servers_to_scans:
        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=network_config,
            scan_commands=parsed_command_line.scan_commands,
            scan_commands_extra_arguments=parsed_command_line.scan_commands_extra_arguments,
        )
        all_server_scan_requests.append(scan_request)

    # If there are servers that we were able to resolve, scan them
    all_server_scan_results = []
    if all_server_scan_requests:
        sslyze_scanner.queue_scans(all_server_scan_requests)
        # Results are actually displayed by the observer; here we just store them
        all_server_scan_results = list(sslyze_scanner.get_results())

    # Write results to a JSON file if needed
    json_file_out: TextIO | None = None
    if parsed_command_line.should_print_json_to_console:
        json_file_out = sys.stdout
    elif parsed_command_line.json_path_out:
        json_file_out = parsed_command_line.json_path_out.open("wt", encoding="utf-8")

    if json_file_out:
        json_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.model_validate(result) for result in all_server_scan_results],
            invalid_server_strings=[
                InvalidServerStringAsJson.model_validate(bad_server)
                for bad_server in parsed_command_line.invalid_servers
            ],
            date_scans_started=date_scans_started,
            date_scans_completed=datetime.now(timezone.utc),
        )
        json_output_as_str = json_output.model_dump_json(indent=2)
        json_file_out.write(json_output_as_str)

    # If we printed the JSON results to the console, don't run the TLS compliance check so we return valid JSON
    if parsed_command_line.should_print_json_to_console:
        sys.exit(0)

    if {res.connectivity_status for res in all_server_scan_results} in [set(), {ServerConnectivityStatusEnum.ERROR}]:
        # There are no results to present: all supplied server strings were invalid?
        sys.exit(0)

    # Check the results against the TLS config if needed
    are_all_servers_compliant = True
    # TODO(AD): Expose format_title method
    title = ObserverToGenerateConsoleOutput._format_title("Compliance against TLS configuration")
    print()
    print(title)
    if not parsed_command_line.tls_config_to_check_against_as_enum:
        print(
            "    Disabled; use --mozilla_config={old, intermediate, modern} or --custom_tls_config=path/to/profile.json.\n"
        )
    else:
        assert parsed_command_line.tls_config_to_check_against, "Should always be set"

        if parsed_command_line.tls_config_to_check_against_as_enum == TlsConfigurationEnum.CUSTOM:
            print("    Checking results against custom TLS configuration.\n")
        else:
            config_name = parsed_command_line.tls_config_to_check_against_as_enum.value
            print(
                f'    Checking results against Mozilla\'s "{config_name}"'
                f" configuration. See https://ssl-config.mozilla.org/ for more details.\n"
            )

        for server_scan_result in all_server_scan_results:
            try:
                check_server_against_tls_configuration(
                    server_scan_result=server_scan_result,
                    tls_config_to_check_against=parsed_command_line.tls_config_to_check_against,
                )
                print(f"    {server_scan_result.server_location.display_string}: OK - Compliant.\n")

            except ServerNotCompliantWithTlsConfiguration as e:
                are_all_servers_compliant = False
                print(f"    {server_scan_result.server_location.display_string}: FAILED - Not compliant.")
                for criteria, error_description in e.issues.items():
                    print(f"        * {criteria}: {error_description}")
                print()

            except ServerScanResultIncomplete:
                are_all_servers_compliant = False
                print(
                    f"    {server_scan_result.server_location.display_string}: ERROR - Scan did not run successfully;"
                    f" review the scan logs above."
                )

    if not are_all_servers_compliant:
        # Return a non-zero error code to signal failure (for example to fail a CI/CD pipeline)
        sys.exit(1)


if __name__ == "__main__":
    main()
