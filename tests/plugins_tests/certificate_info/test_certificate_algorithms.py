import json
from dataclasses import asdict
from pathlib import Path

from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer

from sslyze import ServerNetworkLocationViaDirectConnection, ServerConnectivityTester, JsonEncoder
from sslyze.plugins.certificate_info.implementation import CertificateInfoImplementation


class TestCertificateAlgorithms:
    @can_only_run_on_linux_64
    def test_rsa_certificate(self):
        # Given a server that is configured with an RSA certificate
        with ModernOpenSslServer() as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, port=server.port, ip_address=server.ip_address
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When running the scan, it succeeds
            scan_result = CertificateInfoImplementation.scan_server(server_info)
            assert scan_result.certificate_deployments[0].received_certificate_chain

            # And the result can be converted to JSON
            result_as_json = json.dumps(asdict(scan_result), cls=JsonEncoder)
            assert result_as_json

            # And the result can be converted to console output
            result_as_txt = CertificateInfoImplementation.cli_connector_cls.result_to_console_output(scan_result)
            assert result_as_txt

    @can_only_run_on_linux_64
    def test_ed25519_certificate(self):
        # Given a server that is configured with an ED25519 certificate
        with ModernOpenSslServer(
            server_certificate_path=Path(__file__).parent.absolute() / "server-ed25519-cert.pem",
            server_key_path=Path(__file__).parent.absolute() / "server-ed25519-key.pem",
        ) as server:
            server_location = ServerNetworkLocationViaDirectConnection(
                hostname=server.hostname, port=server.port, ip_address=server.ip_address
            )
            server_info = ServerConnectivityTester().perform(server_location)

            # When running the scan, it succeeds
            scan_result = CertificateInfoImplementation.scan_server(server_info)
            assert scan_result.certificate_deployments[0].received_certificate_chain

            # And the result can be converted to JSON
            result_as_json = json.dumps(asdict(scan_result), cls=JsonEncoder)
            assert result_as_json

            # And the result can be converted to console output
            result_as_txt = CertificateInfoImplementation.cli_connector_cls.result_to_console_output(scan_result)
            assert result_as_txt

    def test_ecdsa_certificate(self):
        # Given a server to scan that has an ECDSA certificate
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.cloudflare.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When running the scan, it succeeds
        scan_result = CertificateInfoImplementation.scan_server(server_info)

        # And the result can be converted to JSON
        result_as_json = json.dumps(asdict(scan_result), cls=JsonEncoder)
        assert result_as_json

        # And the result can be converted to console output
        result_as_txt = CertificateInfoImplementation.cli_connector_cls.result_to_console_output(scan_result)
        assert result_as_txt
