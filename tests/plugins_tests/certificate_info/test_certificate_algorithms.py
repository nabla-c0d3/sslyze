from pathlib import Path
from unittest import mock
from unittest.mock import PropertyMock

import cryptography
import pytest

from sslyze.plugins.certificate_info.json_output import CertificateInfoScanResultAsJson
from tests.connectivity_utils import check_connectivity_to_server_and_return_info
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import ModernOpenSslServer

from sslyze import ServerNetworkLocation
from sslyze.plugins.certificate_info.implementation import CertificateInfoImplementation


class TestCertificateAlgorithms:
    @can_only_run_on_linux_64
    def test_rsa_certificate(self):
        # Given a server that is configured with an RSA certificate
        with ModernOpenSslServer() as server:
            server_location = ServerNetworkLocation(
                hostname=server.hostname, port=server.port, ip_address=server.ip_address
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When running the scan, it succeeds
            scan_result = CertificateInfoImplementation.scan_server(server_info)
            assert scan_result.certificate_deployments[0].received_certificate_chain

            # And the result can be converted to JSON
            result_as_json = CertificateInfoScanResultAsJson.from_orm(scan_result).json()
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
            server_location = ServerNetworkLocation(
                hostname=server.hostname, port=server.port, ip_address=server.ip_address
            )
            server_info = check_connectivity_to_server_and_return_info(server_location)

            # When running the scan, it succeeds
            scan_result = CertificateInfoImplementation.scan_server(server_info)
            assert scan_result.certificate_deployments[0].received_certificate_chain

            # And the result can be converted to JSON
            result_as_json = CertificateInfoScanResultAsJson.from_orm(scan_result).json()
            assert result_as_json

            # And the result can be converted to console output
            result_as_txt = CertificateInfoImplementation.cli_connector_cls.result_to_console_output(scan_result)
            assert result_as_txt

    def test_ecdsa_certificate(self):
        # Given a server to scan that has an ECDSA certificate
        server_location = ServerNetworkLocation("www.cloudflare.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # When running the scan, it succeeds
        scan_result = CertificateInfoImplementation.scan_server(server_info)

        # And the result can be converted to JSON
        result_as_json = CertificateInfoScanResultAsJson.from_orm(scan_result).json()
        assert result_as_json

        # And the result can be converted to console output
        result_as_txt = CertificateInfoImplementation.cli_connector_cls.result_to_console_output(scan_result)
        assert result_as_txt

    @pytest.mark.parametrize("certificate_name_field", ["subject", "issuer"])
    def test_invalid_certificate_bad_name(self, certificate_name_field):
        # Given a server to scan
        server_location = ServerNetworkLocation("www.cloudflare.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)

        # And the server has a certificate with an invalid Subject field
        with mock.patch.object(
            cryptography.x509.Certificate, certificate_name_field, new_callable=PropertyMock
        ) as mock_certificate_name:
            # https://github.com/nabla-c0d3/sslyze/issues/495
            mock_certificate_name.side_effect = ValueError("Country name must be a 2 character country code")

            # When running the scan, it succeeds
            scan_result = CertificateInfoImplementation.scan_server(server_info)

            # And the result can be converted to console output
            result_as_txt = CertificateInfoImplementation.cli_connector_cls.result_to_console_output(scan_result)
            assert result_as_txt

            # And the result can be converted to JSON
            result_as_json = CertificateInfoScanResultAsJson.from_orm(scan_result).json()
            assert result_as_json
