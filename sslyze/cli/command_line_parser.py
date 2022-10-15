from dataclasses import dataclass
from argparse import ArgumentParser
from pathlib import Path

from nassl.ssl_client import OpenSslFileTypeEnum
from typing import Set, List, Optional, Dict
from typing import Tuple

from sslyze.cli.server_string_parser import (
    InvalidServerStringError,
    CommandLineServerStringParser,
)
from sslyze.connection_helpers.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum
from sslyze.mozilla_tls_profile.mozilla_config_checker import (
    MozillaTlsConfigurationEnum,
    SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER,
)
from sslyze.plugins import plugin_base
from sslyze.plugins.certificate_info.trust_stores.trust_store_repository import TrustStoresRepository
from sslyze.plugins.plugin_base import OptParseCliOption
from sslyze.plugins.scan_commands import ScanCommand, ScanCommandsRepository
from sslyze.scanner.models import ScanCommandsExtraArguments

from sslyze.server_setting import (
    HttpProxySettings,
    ServerNetworkLocation,
    ServerNetworkConfiguration,
    InvalidServerNetworkConfigurationError,
    ServerHostnameCouldNotBeResolved,
    ClientAuthenticationCredentials,
)


class CommandLineParsingError(Exception):

    PARSING_ERROR_FORMAT = "  Command line error: {0}\n  Use -h for help."

    def get_error_msg(self) -> str:
        return self.PARSING_ERROR_FORMAT.format(self)


# Not actually an error but makes handling trust store updates a lot easier
class TrustStoresUpdateCompleted(CommandLineParsingError):
    def get_error_msg(self) -> str:
        return "Trust stores successfully updated."


@dataclass(frozen=True)
class ParsedCommandLine:
    """The result of parsing a command line used to launch sslyze."""

    invalid_servers: List[InvalidServerStringError]

    # Servers to scan
    servers_to_scans: List[Tuple[ServerNetworkLocation, ServerNetworkConfiguration]]
    scan_commands: Set[ScanCommand]
    scan_commands_extra_arguments: ScanCommandsExtraArguments

    # Output settings
    json_path_out: Optional[Path]
    should_print_json_to_console: bool
    should_disable_console_output: bool

    # Network settings
    per_server_concurrent_connections_limit: Optional[int]
    concurrent_server_scans_limit: Optional[int]

    # Mozilla compliance; None if shouldn't be run
    check_against_mozilla_config: Optional[MozillaTlsConfigurationEnum]


_STARTTLS_PROTOCOL_DICT = {
    "smtp": ProtocolWithOpportunisticTlsEnum.SMTP,
    "xmpp": ProtocolWithOpportunisticTlsEnum.XMPP,
    "xmpp_server": ProtocolWithOpportunisticTlsEnum.XMPP_SERVER,
    "pop3": ProtocolWithOpportunisticTlsEnum.POP3,
    "imap": ProtocolWithOpportunisticTlsEnum.IMAP,
    "ftp": ProtocolWithOpportunisticTlsEnum.FTP,
    "ldap": ProtocolWithOpportunisticTlsEnum.LDAP,
    "rdp": ProtocolWithOpportunisticTlsEnum.RDP,
    "postgres": ProtocolWithOpportunisticTlsEnum.POSTGRES,
}


class CommandLineParser:
    def __init__(self, sslyze_version: str) -> None:
        """Generate SSLyze's command line parser."""
        self._parser = ArgumentParser(prog="sslyze", description=f"SSLyze version {sslyze_version}")

        # Add generic command line options to the parser
        self._add_default_options()

        # Add plugin .ie scan command options to the parser
        scan_commands_group = self._parser.add_argument_group("Scan commands")
        for scan_option in self._get_plugin_scan_commands():
            scan_commands_group.add_argument(
                f"--{scan_option.option}",
                help=scan_option.help,
                action=scan_option.action,
            )

        self._parser.add_argument(
            "--mozilla_config",
            action="store",
            dest="mozilla_config",
            choices=[config.value for config in MozillaTlsConfigurationEnum] + ["disable"],
            help="Shortcut to queue various scan commands needed to check the server's TLS configurations against one"
            ' of Mozilla\'s recommended TLS configuration. Set to "intermediate" by default. Use "disable" to disable'
            " this check.",
        )

        self._parser.add_argument(dest="target", default=[], nargs="*", help="The list of servers to scan.")

    def parse_command_line(self) -> ParsedCommandLine:
        """Parses the command line used to launch SSLyze."""
        args_command_list = self._parser.parse_args()
        args_target_list = []

        if args_command_list.update_trust_stores:
            # Just update the trust stores and do nothing
            TrustStoresRepository.update_default()
            raise TrustStoresUpdateCompleted()

        # Handle the --targets_in command line and fill args_target_list
        if args_command_list.targets_in:
            try:  # Read targets from a file
                with open(args_command_list.targets_in) as f:
                    for target in f.readlines():
                        if target.strip():  # Ignore empty lines
                            if not target.startswith("#"):  # Ignore comment lines
                                args_target_list.append(target.strip())
            except IOError:
                raise CommandLineParsingError(f"Can't read targets from input file '{args_command_list.targets_in}'")

        for target in args_command_list.target:
            args_target_list.append(target)

        if not args_target_list:
            raise CommandLineParsingError("No targets to scan.")

        # Handle the case when no scan commands have been specified: run --mozilla-config=intermediate by default
        if not args_command_list.mozilla_config:
            did_user_enable_some_scan_commands = False
            for scan_command in ScanCommandsRepository.get_all_scan_commands():
                cli_connector_cls = ScanCommandsRepository.get_implementation_cls(scan_command).cli_connector_cls
                is_scan_cmd_enabled, _ = cli_connector_cls.find_cli_options_in_command_line(args_command_list.__dict__)
                if is_scan_cmd_enabled:
                    did_user_enable_some_scan_commands = True
                    break

            if not did_user_enable_some_scan_commands:
                setattr(args_command_list, "mozilla_config", MozillaTlsConfigurationEnum.INTERMEDIATE.value)

        # Enable the commands needed by --mozilla-config
        check_against_mozilla_config: Optional[MozillaTlsConfigurationEnum] = None
        if args_command_list.mozilla_config:
            if args_command_list.mozilla_config == "disable":
                check_against_mozilla_config = None
            else:
                check_against_mozilla_config = MozillaTlsConfigurationEnum(args_command_list.mozilla_config)

            for scan_cmd in SCAN_COMMANDS_NEEDED_BY_MOZILLA_CHECKER:
                cli_connector_cls = ScanCommandsRepository.get_implementation_cls(scan_cmd).cli_connector_cls
                setattr(args_command_list, cli_connector_cls._cli_option, True)

        # Handle JSON settings
        should_print_json_to_console = False
        json_path_out: Optional[Path] = None
        if args_command_list.json_file:
            if args_command_list.json_file == "-":
                if args_command_list.quiet:
                    raise CommandLineParsingError("Cannot use --quiet with --json_out -.")
                should_print_json_to_console = True
            else:
                json_path_out = Path(args_command_list.json_file).absolute()

        # Sanity checks on the client cert options
        client_auth_creds = None
        if bool(args_command_list.cert) ^ bool(args_command_list.key):
            raise CommandLineParsingError("No private key or certificate file were given. See --cert and --key.")

        elif args_command_list.cert:
            # Private key formats
            if args_command_list.keyform == "DER":
                key_type = OpenSslFileTypeEnum.ASN1
            elif args_command_list.keyform == "PEM":
                key_type = OpenSslFileTypeEnum.PEM

            # Let's try to open the cert and key files
            try:
                client_auth_creds = ClientAuthenticationCredentials(
                    certificate_chain_path=Path(args_command_list.cert),
                    key_path=Path(args_command_list.key),
                    key_password=args_command_list.keypass,
                    key_type=key_type,
                )
            except ValueError as e:
                raise CommandLineParsingError("Invalid client authentication settings: {}.".format(e.args[0]))

        # HTTP CONNECT proxy
        http_proxy_settings = None
        if args_command_list.https_tunnel:
            try:
                http_proxy_settings = HttpProxySettings.from_url(args_command_list.https_tunnel)
            except ValueError as e:
                raise CommandLineParsingError("Invalid proxy URL for --https_tunnel: {}.".format(e.args[0]))

        # Create the server location objects for each specified servers
        good_servers: List[Tuple[ServerNetworkLocation, ServerNetworkConfiguration]] = []
        invalid_server_strings: List[InvalidServerStringError] = []
        for server_string in args_target_list:
            try:
                # Parse the string supplied via the CLI for this server
                (
                    hostname,
                    ip_address,
                    port,
                ) = CommandLineServerStringParser.parse_server_string(server_string)
            except InvalidServerStringError as e:
                # The server string is malformed
                invalid_server_strings.append(e)
                continue

            # If not port number was supplied, assume 443
            final_port = port if port else 443

            # Figure out how we're going to connect to the server
            server_location: ServerNetworkLocation
            if http_proxy_settings:
                # Connect to the server via an HTTP proxy
                # A limitation when using the CLI is that only one http_proxy_settings can be specified for all servers
                server_location = ServerNetworkLocation(
                    hostname=hostname,
                    port=final_port,
                    http_proxy_settings=http_proxy_settings,
                )
            else:
                # Connect to the server directly
                if ip_address:
                    server_location = ServerNetworkLocation(
                        hostname=hostname,
                        port=final_port,
                        ip_address=ip_address,
                    )
                else:
                    # No IP address supplied - do a DNS lookup
                    try:
                        server_location = ServerNetworkLocation(
                            hostname=hostname,
                            port=final_port,
                        )
                    except ServerHostnameCouldNotBeResolved:
                        invalid_server_strings.append(
                            InvalidServerStringError(
                                server_string=f"{hostname}:{final_port}",
                                error_message=f"Could not resolve hostname {hostname}",
                            )
                        )
                        continue

            # Figure out extra network config for this server
            # Opportunistic TLS
            opportunistic_tls: Optional[ProtocolWithOpportunisticTlsEnum] = None
            if args_command_list.starttls:
                if args_command_list.starttls == "auto":
                    # Special value to auto-derive the protocol from the port number
                    opportunistic_tls = ProtocolWithOpportunisticTlsEnum.from_default_port(final_port)
                elif args_command_list.starttls in _STARTTLS_PROTOCOL_DICT:
                    opportunistic_tls = _STARTTLS_PROTOCOL_DICT[args_command_list.starttls]
                else:
                    raise CommandLineParsingError(
                        f"StartTLS should be one of: auto, {', '.join(_STARTTLS_PROTOCOL_DICT.keys())}."
                    )

            try:
                sni_hostname = args_command_list.sni if args_command_list.sni else hostname
                network_config = ServerNetworkConfiguration(
                    tls_opportunistic_encryption=opportunistic_tls,
                    tls_server_name_indication=sni_hostname,
                    tls_client_auth_credentials=client_auth_creds,
                    xmpp_to_hostname=args_command_list.xmpp_to,
                )
                good_servers.append((server_location, network_config))
            except InvalidServerNetworkConfigurationError as e:
                raise CommandLineParsingError(e.args[0])

        # Figure out global network settings
        concurrent_server_scans_limit = None
        per_server_concurrent_connections_limit = None
        if args_command_list.https_tunnel:
            # All the connections will go through a single proxy; only scan one server at a time to not DOS the proxy
            concurrent_server_scans_limit = 1
        if args_command_list.slow_connection:
            # Go easy on the servers; only open 2 concurrent connections against each server
            per_server_concurrent_connections_limit = 2

        # Figure out the scan commands that are enabled
        scan_commands: Set[ScanCommand] = set()
        scan_commands_extra_arguments_dict: Dict[ScanCommand, plugin_base.ScanCommandExtraArgument] = {}
        for scan_command in ScanCommandsRepository.get_all_scan_commands():
            cli_connector_cls = ScanCommandsRepository.get_implementation_cls(scan_command).cli_connector_cls
            (
                is_scan_cmd_enabled,
                extra_args,
            ) = cli_connector_cls.find_cli_options_in_command_line(args_command_list.__dict__)
            if is_scan_cmd_enabled:
                scan_commands.add(scan_command)
                if extra_args:
                    scan_commands_extra_arguments_dict[scan_command] = extra_args
        scan_commands_extra_arguments = ScanCommandsExtraArguments(**scan_commands_extra_arguments_dict)  # type: ignore

        return ParsedCommandLine(
            invalid_servers=invalid_server_strings,
            servers_to_scans=good_servers,
            scan_commands=scan_commands,
            scan_commands_extra_arguments=scan_commands_extra_arguments,
            should_print_json_to_console=should_print_json_to_console,
            json_path_out=json_path_out,
            should_disable_console_output=args_command_list.quiet or args_command_list.json_file == "-",
            concurrent_server_scans_limit=concurrent_server_scans_limit,
            per_server_concurrent_connections_limit=per_server_concurrent_connections_limit,
            check_against_mozilla_config=check_against_mozilla_config,
        )

    def _add_default_options(self) -> None:
        """Add default command line options to the parser."""
        # Updating the trust stores
        trust_stores_group = self._parser.add_argument_group("Trust stores options")
        trust_stores_group.add_argument(
            "--update_trust_stores",
            help="Update the default trust stores used by SSLyze. The latest stores will be "
            "downloaded from https://github.com/nabla-c0d3/trust_stores_observatory. This option "
            "is meant to be used separately, and will silence any other command line option "
            "supplied to SSLyze.",
            dest="update_trust_stores",
            action="store_true",
        )

        # Client certificate options
        client_certificate_group = self._parser.add_argument_group("Client certificate options")
        client_certificate_group.add_argument(
            "--cert",
            metavar="CERTIFICATE_FILE",
            help="Client certificate chain filename. The certificates must be in PEM format and "
            "must be sorted starting with the subject's client certificate, followed by "
            "intermediate CA certificates if applicable.",
            dest="cert",
        )
        client_certificate_group.add_argument(
            "--key", metavar="KEY_FILE", help="Client private key filename.", dest="key"
        )
        client_certificate_group.add_argument(
            "--keyform",
            metavar="KEY_FORMAT",
            choices=["DER", "PEM"],
            help="Client private key format. DER or PEM " "(default).",
            dest="keyform",
            default="PEM",
        )
        client_certificate_group.add_argument(
            "--pass",
            metavar="PASSPHRASE",
            help="Client private key passphrase.",
            dest="keypass",
            default="",
        )

        # Input / output
        input_and_output_group = self._parser.add_argument_group("Input and output options")
        # JSON output
        input_and_output_group.add_argument(
            "--json_out",
            metavar="JSON_FILE",
            help="Write the scan results as a JSON document to the file JSON_FILE. If JSON_FILE "
            "is set to '-', the JSON output will instead be printed to stdout. The resulting "
            "JSON file is a serialized version of the ScanResult objects described in SSLyze's "
            "Python API: the nodes and attributes will be the same. "
            "See https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html "
            "for more details.",
            dest="json_file",
            default=None,
        )
        # Read targets from input file
        input_and_output_group.add_argument(
            "--targets_in",
            metavar="TARGET_FILE",
            help="Read the list of targets to scan from the file TARGET_FILE. It should contain "
            "one host:port per line.",
            dest="targets_in",
            default=None,
        )
        # No text output
        input_and_output_group.add_argument(
            "--quiet",
            action="store_true",
            dest="quiet",
            help="Do not output anything to stdout; useful when using --json_out.",
        )

        # Connectivity option group
        connectivity_group = self._parser.add_argument_group("Contectivity options")
        # Connection speed
        connectivity_group.add_argument(
            "--slow_connection",
            help="Greatly reduce the number of concurrent connections initiated by SSLyze. This "
            "will make the scans slower but more reliable if the connection between your host and "
            "the server is slow, or if the server cannot handle many concurrent connections. "
            "Enable this option if you are getting a lot of timeouts or errors.",
            action="store_true",
            dest="slow_connection",
        )
        # HTTP CONNECT Proxy
        connectivity_group.add_argument(
            "--https_tunnel",
            metavar="PROXY_SETTINGS",
            help="Tunnel all traffic to the target server(s) through an HTTP CONNECT proxy. "
            "HTTP_TUNNEL should be the proxy's URL: 'http://USER:PW@HOST:PORT/'. For proxies "
            "requiring authentication, only Basic Authentication is supported.",
            dest="https_tunnel",
            default=None,
        )
        # STARTTLS
        connectivity_group.add_argument(
            "--starttls",
            metavar="PROTOCOL",
            help="Perform a StartTLS handshake when connecting to the target server(s). "
            f"StartTLS should be one of: auto, {', '.join(_STARTTLS_PROTOCOL_DICT.keys())}. The "
            "'auto' option will cause SSLyze to deduce the protocol (ftp, imap, etc.) from the "
            "supplied port number, for each target servers.",
            dest="starttls",
            default=None,
        )
        connectivity_group.add_argument(
            "--xmpp_to",
            metavar="HOSTNAME",
            help="Optional setting for STARTTLS XMPP. XMPP_TO should be the hostname to be put in "
            "the 'to' attribute of the XMPP stream. Default is the server's hostname.",
            dest="xmpp_to",
            default=None,
        )
        # Server Name Indication
        connectivity_group.add_argument(
            "--sni",
            metavar="SERVER_NAME_INDICATION",
            help="Use Server Name Indication to specify the hostname to connect to. Will only "
            "affect TLS 1.0+ connections.",
            dest="sni",
            default=None,
        )

    @staticmethod
    def _get_plugin_scan_commands() -> List[OptParseCliOption]:
        """Retrieve the list of command line options implemented by the plugins currently available."""
        scan_commands_options = []
        for scan_command in ScanCommandsRepository.get_all_scan_commands():
            cli_connector_cls = ScanCommandsRepository.get_implementation_cls(scan_command).cli_connector_cls
            scan_commands_options.extend(cli_connector_cls.get_cli_options())
        return scan_commands_options
