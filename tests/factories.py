from traceback import TracebackException
from typing import Optional, Set, cast

from faker import Faker
from faker.providers import internet

from sslyze.cli.command_line.server_string_parser import InvalidServerStringError
from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.errors import ConnectionToServerFailed
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.scan_commands import ScanCommand, ScanCommandType
from sslyze.scanner import ServerScanResult, ScanCommandErrorsDict, ScanCommandResultsDict
from sslyze.server_connectivity import (
    ServerConnectivityInfo,
    ServerTlsProbingResult,
    ClientAuthRequirementEnum,
    TlsVersionEnum,
)
from sslyze.server_setting import (
    ServerNetworkLocationViaDirectConnection,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerNetworkLocationViaHttpProxy,
    HttpProxySettings,
)

fake = Faker()
fake.add_provider(internet)


class ServerNetworkLocationViaDirectConnectionFactory:
    @staticmethod
    def create() -> ServerNetworkLocationViaDirectConnection:
        return ServerNetworkLocationViaDirectConnection(
            hostname="ûnicôdé." + fake.hostname(), port=443, ip_address=fake.ipv4_private()
        )


class ServerNetworkLocationViaHttpProxyFactory:
    @staticmethod
    def create() -> ServerNetworkLocationViaHttpProxy:
        return ServerNetworkLocationViaHttpProxy(
            hostname="ûnicôdé." + fake.hostname(),
            port=123,
            http_proxy_settings=HttpProxySettings(hostname="prôxy." + fake.hostname(), port=456),
        )


class ServerConnectivityInfoFactory:
    @staticmethod
    def create(
        server_location: Optional[ServerNetworkLocation] = None,
        tls_probing_result: Optional[ServerTlsProbingResult] = None,
    ) -> ServerConnectivityInfo:
        if server_location:
            final_server_location = server_location
        else:
            final_server_location = ServerNetworkLocationViaDirectConnectionFactory.create()

        if tls_probing_result:
            final_tls_probing_result = tls_probing_result
        else:
            final_tls_probing_result = ServerTlsProbingResult(
                highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
                cipher_suite_supported="AES",
                client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
            )

        return ServerConnectivityInfo(
            server_location=final_server_location,
            network_configuration=ServerNetworkConfiguration(tls_server_name_indication=final_server_location.hostname),
            tls_probing_result=final_tls_probing_result,
        )


class ParsedCommandLineFactory:
    @staticmethod
    def create():
        cmd_line = ParsedCommandLine(
            invalid_servers=[InvalidServerStringError(server_string="www.badpãrsing.com", error_message="Pãrsing err")],
            servers_to_scans=[
                (
                    ServerNetworkLocationViaDirectConnectionFactory.create(),
                    ServerNetworkConfiguration(tls_server_name_indication="a.com"),
                ),
                (
                    ServerNetworkLocationViaHttpProxyFactory.create(),
                    ServerNetworkConfiguration(tls_server_name_indication="a.com"),
                ),
            ],
            scan_commands={ScanCommand.TLS_COMPRESSION, ScanCommand.HTTP_HEADERS},
            scan_commands_extra_arguments={},
            json_path_out=None,
            should_print_json_to_console=False,
            should_disable_console_output=False,
            per_server_concurrent_connections_limit=None,
            concurrent_server_scans_limit=None,
        )
        return cmd_line


class ConnectionToServerFailedFactory:
    @staticmethod
    def create():
        return ConnectionToServerFailed(
            server_location=ServerNetworkLocationViaDirectConnectionFactory.create(),
            network_configuration=ServerNetworkConfiguration(tls_server_name_indication="a.com"),
            error_message="This is ân éè error",
        )


class ServerScanResultFactory:
    @staticmethod
    def create(
        server_info: ServerConnectivityInfo = ServerConnectivityInfoFactory.create(),
        scan_commands_results: Optional[ScanCommandResultsDict] = None,
        scan_commands_errors: Optional[ScanCommandErrorsDict] = None,
    ) -> ServerScanResult:
        final_results: ScanCommandResultsDict = (
            scan_commands_results
            if scan_commands_results
            else {ScanCommand.TLS_COMPRESSION: CompressionScanResult(supports_compression=True)}
        )
        final_errors: ScanCommandErrorsDict = scan_commands_errors if scan_commands_errors else {}
        scan_commands: Set[ScanCommandType] = set()
        for scan_cmd in final_results.keys():
            typed_scan_cmd = cast(ScanCommandType, scan_cmd)
            scan_commands.add(typed_scan_cmd)
        for scan_cmd in final_errors.keys():
            scan_commands.add(scan_cmd)

        return ServerScanResult(
            scan_commands_results=final_results,
            scan_commands_errors=final_errors,
            server_info=server_info,
            scan_commands=scan_commands,
            scan_commands_extra_arguments={},
        )


class TracebackExceptionFactory:
    @staticmethod
    def create() -> TracebackException:
        try:
            raise RuntimeError("test")
        except RuntimeError as e:
            traceback_exc = TracebackException.from_exception(e)
        return traceback_exc
