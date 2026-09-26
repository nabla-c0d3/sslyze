from base64 import b64decode
from unittest import mock

from sslyze import ServerNetworkLocation
from sslyze.plugins.encrypted_client_hello_plugin import (
    EncryptedClientHelloImplementation,
    EncryptedClientHelloScanResult,
    EncryptedClientHelloScanResultAsJson,
    _fetch_ech_config_list_from_dns,
)
from sslyze.server_connectivity import (
    ClientAuthRequirementEnum,
    ServerTlsProbingResult,
    TlsVersionEnum,
)
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.factories import ServerConnectivityInfoFactory
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ClientAuthConfigEnum, S_Server_OpenSSL_4_0_0


class TestEncryptedClientHelloPluginWithOnlineServer:
    def test_real_ech_supported(self) -> None:
        # Given a server known to publish a working ECHConfigList via DNS
        server_location = ServerNetworkLocation("crypto.cloudflare.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for ECH support, it succeeds
        result: EncryptedClientHelloScanResult = EncryptedClientHelloImplementation.scan_server(server_info)

        # And the server is reported as genuinely supporting ECH
        assert result.ech_config_list_from_dns
        assert result.is_ech_supported
        assert result.ech_inner_sni == "crypto.cloudflare.com"
        assert result.ech_outer_sni

        # And the server is also reported as responding to GREASE ECH
        assert result.is_grease_supported

        # And the published ECHConfigList is reported as well-formed
        assert not result.is_ech_config_malformed

        # And a CLI output can be generated
        cli_output = EncryptedClientHelloImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output
        assert any("OK" in line for line in cli_output)

        # And the result can be converted to JSON
        result_as_json = EncryptedClientHelloScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_no_ech_published(self) -> None:
        # Given a server that does not publish an ECHConfigList via DNS
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for ECH support, it succeeds
        result: EncryptedClientHelloScanResult = EncryptedClientHelloImplementation.scan_server(server_info)

        # And the server is reported as not having any ECHConfigList to test
        assert result.ech_config_list_from_dns is None
        assert result.is_ech_supported is None
        assert result.ech_inner_sni is None
        assert result.ech_outer_sni is None

        # And the server is reported as not responding to GREASE ECH either
        assert not result.is_grease_supported

        # And there is no ECHConfigList to judge as malformed or not
        assert not result.is_ech_config_malformed

        # And a CLI output can be generated
        cli_output = EncryptedClientHelloImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("does not publish" in line for line in cli_output)

        # And the result can be converted to JSON
        result_as_json = EncryptedClientHelloScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_ech_config_malformed(self) -> None:
        # Given a server that publishes an ECHConfigList via DNS that is well-formed at the SvcParam level but
        # invalid at the ECHConfig level (bad KEM algorithm ID)
        server_location = ServerNetworkLocation("bk1-ng.test.defo.ie", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for ECH support, it succeeds rather than raising
        result: EncryptedClientHelloScanResult = EncryptedClientHelloImplementation.scan_server(server_info)

        # And the server is reported as publishing a malformed ECHConfigList, ie. a DNS misconfiguration
        assert result.ech_config_list_from_dns
        assert result.is_ech_supported is False
        assert result.is_ech_config_malformed
        assert result.ech_inner_sni is None
        assert result.ech_outer_sni is None

        # And a CLI output can be generated, calling out the DNS misconfiguration specifically
        cli_output = EncryptedClientHelloImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("MISCONFIGURED" in line for line in cli_output)

        # And the result can be converted to JSON
        result_as_json = EncryptedClientHelloScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_ech_config_well_formed_but_wrong_server(self) -> None:
        # Given a server that does NOT support ECH at all...
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # ...and an ECHConfigList that is well-formed and valid, but belongs to a different, unrelated server
        foreign_ech_config_list = _fetch_ech_config_list_from_dns("crypto.cloudflare.com")
        assert foreign_ech_config_list is not None

        # When scanning for ECH support, as if that foreign ECHConfigList had been published for this server
        with mock.patch(
            "sslyze.plugins.encrypted_client_hello_plugin._fetch_ech_config_list_from_dns",
            return_value=foreign_ech_config_list,
        ):
            result: EncryptedClientHelloScanResult = EncryptedClientHelloImplementation.scan_server(server_info)

        # It succeeds, and the server is reported as publishing an ECHConfigList that does NOT lead to working ECH,
        # but that config is NOT flagged as malformed since it is well-formed (just for a different server)
        assert result.ech_config_list_from_dns == foreign_ech_config_list
        assert result.is_ech_supported is False
        assert not result.is_ech_config_malformed
        assert result.ech_inner_sni is None
        assert result.ech_outer_sni is None

        # And a CLI output can be generated, explaining that the published config did not work
        cli_output = EncryptedClientHelloImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("did NOT lead to a working ECH handshake" in line for line in cli_output)

        # And the result can be converted to JSON
        result_as_json = EncryptedClientHelloScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json


class TestEncryptedClientHelloPluginWithNoUsableTlsVersion:
    def test_no_tls_1_3(self) -> None:
        # Given a server that does not support TLS 1.3, which ECH requires
        server_info = ServerConnectivityInfoFactory.create(
            tls_probing_result=ServerTlsProbingResult(
                highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
                cipher_suite_supported="AES",
                client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
                supports_ecdh_key_exchange=True,
            )
        )

        # When scanning for ECH support, no scan jobs are queued since there is nothing to test
        all_scan_jobs = EncryptedClientHelloImplementation.scan_jobs_for_scan_command(server_info)
        assert all_scan_jobs == []

        # And the result can still be generated, without making any network connection
        result = EncryptedClientHelloImplementation.result_for_completed_scan_jobs(server_info, [])

        # And the result reports that nothing could be tested
        assert result.ech_config_list_from_dns is None
        assert result.is_ech_supported is None
        assert result.ech_inner_sni is None
        assert result.ech_outer_sni is None
        assert not result.is_grease_supported
        assert not result.is_ech_config_malformed

        # And a CLI output can still be generated
        cli_output = EncryptedClientHelloImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output

        # And the result can be converted to JSON
        result_as_json = EncryptedClientHelloScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json


def _get_local_ech_config_list() -> bytes:
    # Extract the raw ECHConfigList bytes from the "ECHCONFIG" PEM section, generated using:
    # openssl ech -public_name localhost -out ech-config.pem
    pem_text = S_Server_OpenSSL_4_0_0.ECH_CONFIG_PATH.read_text()
    pem_body = pem_text.split("-----BEGIN ECHCONFIG-----")[1].split("-----END ECHCONFIG-----")[0]
    return b64decode(pem_body.strip())


@can_only_run_on_linux_64
class TestEncryptedClientHelloPluginWithLocalServer:
    def test_client_certificate_requested_lol(self) -> None:
        # Given a server that supports ECH and requires client authentication
        with S_Server_OpenSSL_4_0_0(client_auth_config=ClientAuthConfigEnum.REQUIRED, enable_ech=True) as server:
            # And sslyze does NOT provide a client certificate
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # And the server's real ECHConfigList is used, as if it had been published in the server's DNS record
            local_ech_config_list = _get_local_ech_config_list()
            with mock.patch(
                "sslyze.plugins.encrypted_client_hello_plugin._fetch_ech_config_list_from_dns",
                return_value=local_ech_config_list,
            ):
                # When scanning for ECH support, it succeeds despite the missing client certificate
                result: EncryptedClientHelloScanResult = EncryptedClientHelloImplementation.scan_server(server_info)

        # And the server is reported as genuinely supporting ECH: ECH is negotiated in the ClientHello and
        # ServerHello, which complete before the server asks for (and sslyze fails to provide) a client certificate
        assert result.is_ech_supported
        assert result.ech_inner_sni == server.hostname
        assert not result.is_ech_config_malformed

        # And a CLI output can be generated
        cli_output = EncryptedClientHelloImplementation.cli_connector_cls.result_to_console_output(result)
        assert any("Server supports ECH" in line for line in cli_output)

        # And the result can be converted to JSON
        result_as_json = EncryptedClientHelloScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json
