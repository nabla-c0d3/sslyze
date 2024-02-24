import random

import pytest
from nassl.ephemeral_key_info import EcDhEphemeralKeyInfo

from sslyze.connection_helpers.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum
from sslyze.plugins.openssl_cipher_suites.implementation import (
    Sslv20ScanImplementation,
    CipherSuitesScanResult,
    Sslv30ScanImplementation,
    Tlsv10ScanImplementation,
    Tlsv11ScanImplementation,
    Tlsv12ScanImplementation,
    Tlsv13ScanImplementation,
)
from sslyze.plugins.openssl_cipher_suites.json_output import CipherSuitesScanResultAsJson

from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ModernOpenSslServer, ClientAuthConfigEnum


# Tests for the legacy cipher suite preference test, which was removed and will be turned into a full-fledged plugin
# https://github.com/nabla-c0d3/sslyze/issues/338
@pytest.mark.skip("Re-enable these tests when implementing cipher suite preference (#338)")
class DisabledTestCipherSuitePreference:
    def test_cipher_suite_preferred_by_server(self) -> None:
        # Given an ordered list of cipher suites
        configured_cipher_suites = [
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-SHA256",
            "AES256-SHA256",
            "AES128-SHA",
            "AES256-SHA",
        ]
        random.shuffle(configured_cipher_suites)
        cipher_string = ":".join(configured_cipher_suites)

        # And a server that is configured with this list as its prefered cipher suites
        with ModernOpenSslServer(
            openssl_cipher_string=cipher_string, should_enable_server_cipher_preference=True
        ) as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When scanning for cipher suites, it succeeds
            result: CipherSuitesScanResult = Tlsv12ScanImplementation.scan_server(server_info)

        # And the server's cipher suite preference was detected
        pref_by_server = result.cipher_suite_preferred_by_server  # type: ignore
        assert pref_by_server
        assert configured_cipher_suites[0] == pref_by_server.cipher_suite.openssl_name

    def test_follows_client_cipher_suite_preference(self) -> None:
        # Given a server to scan that follows client cipher suite preference
        server_location = ServerNetworkLocation("www.hotmail.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.scan_server(server_info)

        # And the server is detected as following the client's preference
        assert result.cipher_suite_preferred_by_server  # type: ignore


class TestCipherSuitesPluginWithOnlineServer:
    def test_sslv2_disabled(self) -> None:
        # Given a server to scan that does not support SSL 2.0
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Sslv20ScanImplementation.scan_server(server_info)

        # And the result confirms that SSL 2.0 is not supported
        assert not result.accepted_cipher_suites
        assert result.rejected_cipher_suites

        # And a CLI output can be generated
        assert Sslv20ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_sslv3_disabled(self) -> None:
        # Given a server to scan that does not support SSL 3.0
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Sslv30ScanImplementation.scan_server(server_info)

        # And the result confirms that SSL 3.0 is not supported
        assert not result.accepted_cipher_suites
        assert result.rejected_cipher_suites

        # And a CLI output can be generated
        assert Sslv30ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_tlsv1_0_enabled(self) -> None:
        # Given a server to scan that supports TLS 1.0
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv10ScanImplementation.scan_server(server_info)

        # And the result confirms that TLS 1.0 is supported
        expected_ciphers = {
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        }
        assert expected_ciphers == {
            accepted_cipher.cipher_suite.name for accepted_cipher in result.accepted_cipher_suites
        }

        assert result.rejected_cipher_suites

        # And a CLI output can be generated
        assert Tlsv10ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_tlsv1_0_disabled(self) -> None:
        # Given a server to scan that does NOT support TLS 1.0
        server_location = ServerNetworkLocation("success.trendmicro.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv10ScanImplementation.scan_server(server_info)

        # And the result confirms that TLS 1.0 is not supported
        assert not result.accepted_cipher_suites
        assert result.rejected_cipher_suites

        # And a CLI output can be generated
        assert Tlsv10ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_tlsv1_1_enabled(self) -> None:
        # Given a server to scan that supports TLS 1.1
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv11ScanImplementation.scan_server(server_info)

        # And the result confirms that TLS 1.1 is not supported
        expected_ciphers = {
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        }
        assert expected_ciphers == {
            accepted_cipher.cipher_suite.name for accepted_cipher in result.accepted_cipher_suites
        }

        assert result.rejected_cipher_suites

        # And a CLI output can be generated
        assert Tlsv11ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_tlsv1_2_enabled(self) -> None:
        # Given a server to scan that supports TLS 1.2
        server_location = ServerNetworkLocation("www.google.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.scan_server(server_info)

        # And the result confirms that TLS 1.2 is supported
        expected_ciphers = {
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        }
        assert expected_ciphers == {
            accepted_cipher.cipher_suite.name for accepted_cipher in result.accepted_cipher_suites
        }

        # And a CLI output can be generated
        assert Tlsv12ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_null_cipher_suites(self) -> None:
        # Given a server to scan that supports NULL cipher suites
        server_location = ServerNetworkLocation("null.badssl.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.scan_server(server_info)

        # And the NULL/Anon cipher suites were detected
        expected_ciphers = {
            "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
            "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
            "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
            "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
            "TLS_DH_anon_WITH_AES_256_CBC_SHA",
            "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
            "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
            "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
            "TLS_DH_anon_WITH_SEED_CBC_SHA",
            "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_NULL_SHA",
            "TLS_ECDH_anon_WITH_NULL_SHA",
            "TLS_RSA_WITH_NULL_SHA256",
            "TLS_RSA_WITH_NULL_SHA",
        }
        assert expected_ciphers == {
            accepted_cipher.cipher_suite.name for accepted_cipher in result.accepted_cipher_suites
        }

        # And a CLI output can be generated
        assert Tlsv12ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_rc4_cipher_suites(self) -> None:
        # Given a server to scan that supports RC4 cipher suites
        server_location = ServerNetworkLocation("rc4.badssl.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.scan_server(server_info)

        # And the RC4 cipher suites were detected
        assert {"TLS_ECDHE_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_RC4_128_SHA"} == {
            accepted_cipher.cipher_suite.name for accepted_cipher in result.accepted_cipher_suites
        }

        # And a CLI output can be generated
        assert Tlsv12ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_ecdsa_cipher_suites(self) -> None:
        # Given a server to scan that supports ECDSA cipher suites
        server_location = ServerNetworkLocation("ecc256.badssl.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.scan_server(server_info)

        # And the RC4 cipher suites were detected
        expected_ciphers = {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        }
        assert expected_ciphers == {
            accepted_cipher.cipher_suite.name for accepted_cipher in result.accepted_cipher_suites
        }

        # And a CLI output can be generated
        assert Tlsv12ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_smtp(self) -> None:
        # Given an SMTP server to scan
        hostname = "smtp.gmail.com"
        server_location = ServerNetworkLocation(hostname, 587)
        network_configuration = ServerNetworkConfiguration(
            tls_server_name_indication=hostname, tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.SMTP
        )
        server_info = check_connectivity_to_server_and_return_info(server_location, network_configuration)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.scan_server(server_info)
        assert result.accepted_cipher_suites

        # And a CLI output can be generated
        assert Tlsv12ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_tls_1_3_cipher_suites(self) -> None:
        # Given a server to scan that supports TLS 1.3
        server_location = ServerNetworkLocation("www.cloudflare.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv13ScanImplementation.scan_server(server_info)
        assert result.accepted_cipher_suites

        assert {"TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"} == {
            accepted_cipher.cipher_suite.name for accepted_cipher in result.accepted_cipher_suites
        }

        # And a CLI output can be generated
        assert Tlsv13ScanImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = CipherSuitesScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json

    def test_ephemeral_key_info(self) -> None:
        # Given a server to scan that supports DH and ECDH ephemeral keys
        server_location = ServerNetworkLocation("cloudflare.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.scan_server(server_info)

        # And the ephemeral keys for ECDHE were returned
        assert result.accepted_cipher_suites
        found_ecdh_key = False
        for accepted_cipher_suite in result.accepted_cipher_suites:
            if "_ECDHE_" in accepted_cipher_suite.cipher_suite.name:
                assert isinstance(accepted_cipher_suite.ephemeral_key, EcDhEphemeralKeyInfo)
                found_ecdh_key = True
        assert found_ecdh_key


@can_only_run_on_linux_64
class TestCipherSuitesPluginWithLocalServer:
    def test_sslv2_enabled(self) -> None:
        # Given a server to scan that supports SSL 2.0
        with LegacyOpenSslServer(openssl_cipher_string="ALL:COMPLEMENTOFALL") as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When scanning for cipher suites, it succeeds
            result: CipherSuitesScanResult = Sslv20ScanImplementation.scan_server(server_info)

        # The right cipher suites were detected
        assert len(result.accepted_cipher_suites) == 7
        assert not result.rejected_cipher_suites

    def test_sslv3_enabled(self) -> None:
        # Given a server to scan that supports SSL 3.0
        with LegacyOpenSslServer(openssl_cipher_string="ALL:COMPLEMENTOFALL") as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When scanning for cipher suites, it succeeds
            result: CipherSuitesScanResult = Sslv30ScanImplementation.scan_server(server_info)

        # The right cipher suites were detected
        assert len(result.accepted_cipher_suites) == 43
        assert result.rejected_cipher_suites

    def test_succeeds_when_client_auth_failed_tls_1_2(self) -> None:
        # Given a TLS 1.2 server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And SSLyze does NOT provide a client certificate
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When scanning for cipher suites, it succeeds
            result: CipherSuitesScanResult = Tlsv12ScanImplementation.scan_server(server_info)

        assert result.accepted_cipher_suites

    def test_succeeds_when_client_auth_failed_tls_1_3(self) -> None:
        # Given a TLS 1.3 server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And SSLyze does NOT provide a client certificate
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When scanning for cipher suites, it succeeds
            result: CipherSuitesScanResult = Tlsv13ScanImplementation.scan_server(server_info)

        assert result.accepted_cipher_suites
