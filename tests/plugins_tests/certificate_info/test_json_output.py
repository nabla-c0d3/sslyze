from dataclasses import dataclass, asdict
from io import StringIO

import cryptography

from sslyze.cli.json_output import JsonOutputGenerator
from sslyze.plugins.certificate_info.cli_connector import _CertificateInfoCliConnector
from sslyze.plugins.certificate_info.core import CertificateInfoImplementation
from sslyze.plugins.scan_commands import ScanCommandEnum
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.factories import ServerScanResultFactory


class TestJsonOutput:
    def test_json_serializer_functions(self):
        _CertificateInfoCliConnector.register_json_serializer_functions()

        # Given a server to scan
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.hotmail.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When running the scan with the custom CA file enabled
        plugin_result = CertificateInfoImplementation.perform(server_info)

        # Given a completed scan for a server
        scan_results = {ScanCommandEnum.CERTIFICATE_INFO: plugin_result}
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
        assert "notBefore" in final_output
