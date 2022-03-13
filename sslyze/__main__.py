import sys
from datetime import datetime
from typing import Optional, TextIO

from sslyze.cli.console_output import ObserverToGenerateConsoleOutput
from sslyze.__version__ import __version__
from sslyze.cli.command_line_parser import CommandLineParsingError, CommandLineParser

from sslyze import (
    Scanner,
    ServerScanRequest,
    SslyzeOutputAsJson,
    ServerScanResultAsJson,
)
from sslyze.json.json_output import InvalidServerStringAsJson
from sslyze.mozilla_tls_profile.mozilla_config_checker import (
    MozillaTlsConfigurationChecker,
    ServerNotCompliantWithMozillaTlsConfiguration,
    ServerScanResultIncomplete,
)


def main() -> None:
    # Parse the supplied command line
    date_scans_started = datetime.utcnow()
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
        for result in sslyze_scanner.get_results():
            # Results are actually displayed by the observer; here we just store them
            all_server_scan_results.append(result)

    # Write results to a JSON file if needed
    json_file_out: Optional[TextIO] = None
    if parsed_command_line.should_print_json_to_console:
        json_file_out = sys.stdout
    elif parsed_command_line.json_path_out:
        json_file_out = parsed_command_line.json_path_out.open("wt", encoding="utf-8")

    if json_file_out:
        json_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.from_orm(result) for result in all_server_scan_results],
            invalid_server_strings=[
                InvalidServerStringAsJson.from_orm(bad_server) for bad_server in parsed_command_line.invalid_servers
            ],
            date_scans_started=date_scans_started,
            date_scans_completed=datetime.utcnow(),
        )
        json_output_as_str = json_output.json(sort_keys=True, indent=4, ensure_ascii=True)
        json_file_out.write(json_output_as_str)

    # If we printed the JSON results to the console, don't run the Mozilla compliance check so we return valid JSON
    if parsed_command_line.should_print_json_to_console:
        sys.exit(0)

    if not all_server_scan_results:
        # There are no results to present: all supplied server strings were invalid?
        sys.exit(0)

    # Check the results against the Mozilla config if needed
    are_all_servers_compliant = True
    # TODO(AD): Expose format_title method
    title = ObserverToGenerateConsoleOutput._format_title("Compliance against Mozilla TLS configuration")
    print()
    print(title)
    if not parsed_command_line.check_against_mozilla_config:
        print("    Disabled; use --mozilla_config={old, intermediate, modern}.\n")
    else:

        print(
            f'    Checking results against Mozilla\'s "{parsed_command_line.check_against_mozilla_config}"'
            f" configuration. See https://ssl-config.mozilla.org/ for more details.\n"
        )
        mozilla_checker = MozillaTlsConfigurationChecker.get_default()
        for server_scan_result in all_server_scan_results:
            try:
                mozilla_checker.check_server(
                    against_config=parsed_command_line.check_against_mozilla_config,
                    server_scan_result=server_scan_result,
                )
                print(f"    {server_scan_result.server_location.display_string}: OK - Compliant.\n")

            except ServerNotCompliantWithMozillaTlsConfiguration as e:
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
