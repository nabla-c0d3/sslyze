from io import StringIO

from sslyze.cli.json_output import JsonOutputGenerator
from sslyze.plugins.certificate_info.implementation import CertificateInfoImplementation
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.factories import ServerScanResultFactory


class TestJsonOutput:
    def test_json_serializer_functions(self):
        # Given a completed scan for a server with the CERTIFICATE_INFO scan command
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.facebook.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)
        plugin_result = CertificateInfoImplementation.scan_server(server_info)
        scan_results = {ScanCommand.CERTIFICATE_INFO: plugin_result}
        scan_result = ServerScanResultFactory.create(scan_commands_results=scan_results)

        # When generating the JSON output for this server scan
        with StringIO() as file_out:
            json_generator = JsonOutputGenerator(file_to=file_out)
            json_generator.server_scan_completed(scan_result)

            # We call scans_completed() because this is when the output actually gets written to the file
            json_generator.scans_completed(0.2)
            final_output = file_out.getvalue()

        # It succeeds
        assert final_output

        # And complex object like certificates were properly serialized
        assert "notBefore" in final_output
        assert "issuer" in final_output
        assert "subject" in final_output
