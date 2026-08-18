from sslyze import ServerNetworkLocation
from sslyze.plugins.signature_algorithms_plugin import (
    SignatureAlgorithm,
    SignatureAlgorithmsImplementation,
    SignatureAlgorithmsScanResult,
    SignatureAlgorithmsScanResultAsJson,
)
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer


class TestSignatureAlgorithmsPluginWithOnlineServer:
    def test_supported_signature_algorithms(self) -> None:
        # Given a server to scan
        server_location = ServerNetworkLocation("www.cloudflare.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When scanning for supported signature algorithms, it succeeds
        result: SignatureAlgorithmsScanResult = SignatureAlgorithmsImplementation.scan_server(server_info)

        # And the result confirms that some algorithms are supported and some are not
        assert result.supported_signature_algorithms
        assert result.rejected_signature_algorithms

        # And a CLI output can be generated
        assert SignatureAlgorithmsImplementation.cli_connector_cls.result_to_console_output(result)

        # And the result can be converted to JSON
        result_as_json = SignatureAlgorithmsScanResultAsJson.model_validate(result).model_dump_json()
        assert result_as_json


class TestSignatureAlgorithmsResultSerialization:
    def test_console_and_json_round_trip(self) -> None:
        # Given a result built without any network connection
        result = SignatureAlgorithmsScanResult(
            supported_signature_algorithms=[
                SignatureAlgorithm.RSA_PSS_RSAE_SHA256,
                SignatureAlgorithm.RSA_PKCS1_SHA256,
            ],
            rejected_signature_algorithms=[SignatureAlgorithm.ECDSA_SHA256],
        )

        # When generating the CLI output, it lists the algorithms
        cli_output = SignatureAlgorithmsImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output
        assert any(SignatureAlgorithm.RSA_PSS_RSAE_SHA256.value in line for line in cli_output)

        # And the result can be serialized to JSON and keeps the algorithm names
        result_as_json = SignatureAlgorithmsScanResultAsJson.model_validate(result).model_dump_json()
        assert SignatureAlgorithm.RSA_PSS_RSAE_SHA256.value in result_as_json
        assert SignatureAlgorithm.ECDSA_SHA256.value in result_as_json

    def test_empty_result_console_output(self) -> None:
        # Given a result where the server accepted nothing
        result = SignatureAlgorithmsScanResult(
            supported_signature_algorithms=[],
            rejected_signature_algorithms=[SignatureAlgorithm.RSA_PKCS1_SHA1],
        )

        # When generating the CLI output, it still works and flags the absence
        cli_output = SignatureAlgorithmsImplementation.cli_connector_cls.result_to_console_output(result)
        assert cli_output
        assert any("did not accept" in line for line in cli_output)


@can_only_run_on_linux_64
class TestSignatureAlgorithmsPluginWithLocalServer:
    def test_supported_signature_algorithms(self) -> None:
        # Given a local server with an RSA certificate
        with ModernOpenSslServer() as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, ip_address=server.ip_address, port=server.port
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When scanning the server for supported signature algorithms, it succeeds
            result: SignatureAlgorithmsScanResult = SignatureAlgorithmsImplementation.scan_server(server_info)

        # And an RSA-PSS algorithm was detected as supported (the server has an RSA certificate)
        assert SignatureAlgorithm.RSA_PSS_RSAE_SHA256 in result.supported_signature_algorithms

        # And no ECDSA algorithm was accepted since the server does not have an ECDSA certificate
        ecdsa_algorithms = {
            SignatureAlgorithm.ECDSA_SHA1,
            SignatureAlgorithm.ECDSA_SHA224,
            SignatureAlgorithm.ECDSA_SHA256,
            SignatureAlgorithm.ECDSA_SHA384,
            SignatureAlgorithm.ECDSA_SHA512,
        }
        assert not ecdsa_algorithms.intersection(result.supported_signature_algorithms)
