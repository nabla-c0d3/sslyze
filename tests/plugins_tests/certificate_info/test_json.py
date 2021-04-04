from sslyze.cli.json_output import ServerScanResultAsJson
from sslyze.plugins.certificate_info.implementation import CertificateInfoImplementation
from sslyze.scanner.server_scan_request import ScanCommandsResults
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.factories import ServerScanResultFactory


class TestJsonEncoder:
    def test(self):
        # Given a completed scan for a server with the CERTIFICATE_INFO scan command
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.facebook.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)
        plugin_result = CertificateInfoImplementation.scan_server(server_info)
        scan_result = ServerScanResultFactory.create(
            scan_commands_results=ScanCommandsResults(certificate_info=plugin_result)
        )

        # When converting it into to JSON
        result_as_json = ServerScanResultAsJson.from_orm(scan_result).json()

        # It succeeds
        assert result_as_json

        # And complex object like certificates were properly serialized
        assert "issuer" in result_as_json
        assert "subject" in result_as_json
