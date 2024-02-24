from sslyze.plugins.certificate_info.implementation import CertificateInfoImplementation
from sslyze.plugins.certificate_info.json_output import CertificateInfoScanResultAsJson
from sslyze.server_setting import ServerNetworkLocation
from tests.connectivity_utils import check_connectivity_to_server_and_return_info


class TestJsonEncoder:
    def test(self):
        # Given a completed scan for a server with the CERTIFICATE_INFO scan command
        server_location = ServerNetworkLocation("www.facebook.com", 443)
        server_info = check_connectivity_to_server_and_return_info(server_location)
        plugin_result = CertificateInfoImplementation.scan_server(server_info)

        # When converting it to JSON
        result_as_json = CertificateInfoScanResultAsJson.model_validate(plugin_result).model_dump_json()

        # It succeeds
        assert result_as_json

        # And complex object like certificates were properly serialized
        assert "issuer" in result_as_json
        assert "subject" in result_as_json
