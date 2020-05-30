import json
from dataclasses import asdict

import sslyze
from sslyze.plugins.certificate_info.implementation import CertificateInfoImplementation
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.factories import ServerScanResultFactory


class TestJsonEncoder:
    def test(self):
        # Given a completed scan for a server with the CERTIFICATE_INFO scan command
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.facebook.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)
        plugin_result = CertificateInfoImplementation.scan_server(server_info)
        scan_results = {ScanCommand.CERTIFICATE_INFO: plugin_result}
        scan_result = ServerScanResultFactory.create(scan_commands_results=scan_results)

        # When converting it into to JSON
        result_as_json = json.dumps(asdict(scan_result), cls=sslyze.JsonEncoder)

        # It succeeds
        assert result_as_json

        # And complex object like certificates were properly serialized
        assert "notBefore" in result_as_json
        assert "issuer" in result_as_json
        assert "subject" in result_as_json
