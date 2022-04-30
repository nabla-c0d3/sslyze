import pytest
from nassl.ssl_client import ClientCertificateRequested

from sslyze import TlsResumptionSupportEnum
from sslyze.plugins.session_resumption.implementation import (
    SessionResumptionSupportImplementation,
    SessionResumptionSupportScanResult,
    SessionResumptionSupportExtraArgument,
)

from sslyze.server_setting import (
    ServerNetworkLocation,
    ServerNetworkConfiguration,
    ClientAuthenticationCredentials,
)
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer, ClientAuthConfigEnum, LegacyOpenSslServer


class TestSessionResumptionSupport:
    def test(self):
        # Given a server that supports session resumption with both TLS tickets and session IDs
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When testing for resumption, it succeeds
        result: SessionResumptionSupportScanResult = SessionResumptionSupportImplementation.scan_server(server_info)

        # And it confirms that both session IDs and TLS tickets are supported
        assert result.session_id_resumption_result == TlsResumptionSupportEnum.FULLY_SUPPORTED
        assert result.session_id_attempted_resumptions_count
        assert result.session_id_successful_resumptions_count

        assert result.tls_ticket_resumption_result == TlsResumptionSupportEnum.FULLY_SUPPORTED
        assert result.tls_ticket_attempted_resumptions_count
        assert result.tls_ticket_successful_resumptions_count

        # And a CLI output can be generated
        assert SessionResumptionSupportImplementation.cli_connector_cls.result_to_console_output(result)

    def test_with_extra_argument(self):
        # Given a server that supports session resumption with both TLS tickets and session IDs
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # And we customize how many session resumptions to perform
        custom_resumption_attempts_count = 6
        extra_arg = SessionResumptionSupportExtraArgument(
            number_of_resumptions_to_attempt=custom_resumption_attempts_count
        )

        # When testing for resumption, it succeeds
        result: SessionResumptionSupportScanResult = SessionResumptionSupportImplementation.scan_server(
            server_info,
            extra_arguments=extra_arg,
        )

        # And the expected number of resumptions was performed
        assert result.session_id_attempted_resumptions_count == custom_resumption_attempts_count
        assert result.tls_ticket_attempted_resumptions_count == custom_resumption_attempts_count

        # And a CLI output can be generated
        assert SessionResumptionSupportImplementation.cli_connector_cls.result_to_console_output(result)

    @can_only_run_on_linux_64
    def test_fails_when_client_auth_failed(self):
        # Given a server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When testing for resumption, it fails
            with pytest.raises(ClientCertificateRequested):
                SessionResumptionSupportImplementation.scan_server(server_info)

    @can_only_run_on_linux_64
    def test_works_when_client_auth_succeeded(self):
        # Given a server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            # And sslyze provides a client certificate
            network_config = ServerNetworkConfiguration(
                tls_server_name_indication=server.hostname,
                tls_client_auth_credentials=ClientAuthenticationCredentials(
                    certificate_chain_path=server.get_client_certificate_path(), key_path=server.get_client_key_path()
                ),
            )
            server_info = check_connectivity_to_server_and_return_info(server_location, network_config)

            # When testing for resumption, it succeeds
            result: SessionResumptionSupportScanResult = SessionResumptionSupportImplementation.scan_server(server_info)

        assert result.session_id_successful_resumptions_count
        assert result.session_id_resumption_result == TlsResumptionSupportEnum.FULLY_SUPPORTED
