from traceback import TracebackException
from uuid import uuid4

from faker import Faker
from faker.providers import internet

from sslyze import ScanCommandAttemptStatusEnum, ScanCommandsExtraArguments, ServerScanRequest, ServerScanResult
from sslyze.cli.command_line_parser import ParsedCommandLine
from sslyze.cli.server_string_parser import InvalidServerStringError
from sslyze.errors import ConnectionToServerFailed
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner.models import (
    AllScanCommandsAttempts,
    ServerConnectivityStatusEnum,
    ServerScanStatusEnum,
    get_scan_command_attempt_cls,
)
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerConnectivityInfo,
    ServerTlsProbingResult,
    TlsVersionEnum,
)
from sslyze.server_setting import (
    HttpProxySettings,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
)

fake = Faker()
fake.add_provider(internet)


class ServerNetworkLocationViaDirectConnectionFactory:
    @staticmethod
    def create() -> ServerNetworkLocation:
        return ServerNetworkLocation(hostname="ûnicôdé." + fake.hostname(), port=443, ip_address=fake.ipv4_private())


class ServerNetworkLocationViaHttpProxyFactory:
    @staticmethod
    def create() -> ServerNetworkLocation:
        return ServerNetworkLocation(
            hostname="ûnicôdé." + fake.hostname(),
            port=123,
            http_proxy_settings=HttpProxySettings(hostname="prôxy." + fake.hostname(), port=456),
        )


class ServerConnectivityInfoFactory:
    @staticmethod
    def create(
        server_location: ServerNetworkLocation | None = None,
        tls_probing_result: ServerTlsProbingResult | None = None,
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
                supports_ecdh_key_exchange=True,
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
            tls_config_to_check_against_as_enum=None,
            tls_config_to_check_against=None,
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


class AllScanCommandsAttemptsFactory:
    @staticmethod
    def create(all_scan_command_attempts: dict[str, ScanCommandAttempt] | None = None):
        final_all_scan_command_attempts: dict[str, ScanCommandAttempt] = {}
        if all_scan_command_attempts:
            final_all_scan_command_attempts.update(all_scan_command_attempts)

        # Flag the remaining scan command as NOT_SCHEDULED
        for scan_cmd in ScanCommand:
            if scan_cmd.value not in final_all_scan_command_attempts:
                scan_command_attempt_cls = get_scan_command_attempt_cls(scan_cmd)
                final_all_scan_command_attempts[scan_cmd.value] = scan_command_attempt_cls(
                    status=ScanCommandAttemptStatusEnum.NOT_SCHEDULED,
                    error_reason=None,
                    error_trace=None,
                    result=None,
                )

        return AllScanCommandsAttempts(**final_all_scan_command_attempts)  # type: ignore


class ServerScanResultFactory:
    @staticmethod
    def create(
        server_location: ServerNetworkLocation | None = None,
        scan_status: ServerScanStatusEnum = ServerScanStatusEnum.COMPLETED,
        scan_result: AllScanCommandsAttempts | None = None,
    ) -> ServerScanResult:
        final_server_location: ServerNetworkLocation
        if server_location is None:
            final_server_location = ServerNetworkLocationViaDirectConnectionFactory.create()
        else:
            final_server_location = server_location

        network_configuration = ServerNetworkConfiguration.default_for_server_location(final_server_location)

        connectivity_result: ServerTlsProbingResult | None
        if scan_status == ServerScanStatusEnum.COMPLETED:
            connectivity_status = ServerConnectivityStatusEnum.COMPLETED
            connectivity_error_trace = None
            connectivity_result = ServerTlsProbingResultFactory.create()
            if scan_result is None:
                final_scan_result = AllScanCommandsAttemptsFactory.create()
            else:
                final_scan_result = scan_result

        elif scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            connectivity_error_trace = TracebackExceptionFactory.create()
            connectivity_status = ServerConnectivityStatusEnum.ERROR
            connectivity_result = None
            final_scan_result = None

        else:
            raise ValueError("Should never happen")

        return ServerScanResult(
            uuid=uuid4(),
            server_location=final_server_location,
            network_configuration=network_configuration,
            connectivity_status=connectivity_status,
            connectivity_error_trace=connectivity_error_trace,
            connectivity_result=connectivity_result,
            scan_status=scan_status,
            scan_result=final_scan_result,
        )


class TracebackExceptionFactory:
    @staticmethod
    def create() -> TracebackException:
        try:
            raise RuntimeError("test")
        except RuntimeError as e:
            traceback_exc = TracebackException.from_exception(e)
        return traceback_exc


class ServerScanRequestFactory:
    @staticmethod
    def create(
        server_location: ServerNetworkLocation | None = None,
        scan_commands: set[ScanCommand] | None = None,
        scan_commands_extra_arguments: ScanCommandsExtraArguments | None = None,
    ) -> ServerScanRequest:
        final_server_location: ServerNetworkLocation | None
        if server_location is None:
            final_server_location = ServerNetworkLocationViaDirectConnectionFactory.create()
        else:
            final_server_location = server_location

        if scan_commands is None:
            final_scan_commands = {ScanCommand.CERTIFICATE_INFO, ScanCommand.ROBOT}
        else:
            final_scan_commands = scan_commands

        if scan_commands_extra_arguments is None:
            final_extra_args = ScanCommandsExtraArguments()
        else:
            final_extra_args = scan_commands_extra_arguments

        return ServerScanRequest(
            server_location=final_server_location,
            scan_commands=final_scan_commands,
            scan_commands_extra_arguments=final_extra_args,
        )


class ServerTlsProbingResultFactory:
    @staticmethod
    def create(
        client_auth_requirement: ClientAuthRequirementEnum = ClientAuthRequirementEnum.DISABLED,
    ) -> ServerTlsProbingResult:
        return ServerTlsProbingResult(
            highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
            cipher_suite_supported="AES",
            client_auth_requirement=client_auth_requirement,
            supports_ecdh_key_exchange=True,
        )
