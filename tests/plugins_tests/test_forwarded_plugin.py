import pytest
from dataclasses import dataclass
from typing import Dict
from sslyze.plugins.forwarded_plugin import ForwardedImplementation, ForwardedScanResult, _parse_forwarded_header_from_http_response
from sslyze.server_connectivity import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection

@dataclass
class _MockHttpResponse:
    status: int
    _headers: Dict[str, str]

    def getheader(self, name: str, default=None):
        """Replicate HTTPResponse's API.
        """
        return self._headers[name]


class TestForwardedPlugin:
    def test_missing_header(self):
        # Given a server to scan that has TLS compression disabled
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup("www.google.com", 443)
        server_info = ServerConnectivityTester().perform(server_location)

        # When testing for compression support, it succeeds
        result: ForwardedScanResult = ForwardedImplementation.scan_server(server_info)

        # And the right result is returned
        assert not result.forwarded

        # And a CLI output can be generated
        assert ForwardedImplementation.cli_connector_cls.result_to_console_output(result)

    def test_header_parsing(self):
        http_response = _MockHttpResponse(status=200, _headers={"Forwarded": "for=\"FEI_IN_123\"  ; for= \"something_else\" ; by=\"proxy\"; Host=\"local\"; pRoto=\"https\""},)
        result = _parse_forwarded_header_from_http_response(http_response)

        assert result.forwarded_by == ["proxy"]
        assert result.forwarded_for == ["FEI_IN_123", "something_else"]
        assert result.forwarded_host == ["local"]
        assert result.forwarded_proto == ["https"]

    def test_parse_empty_header(self):
        http_response = _MockHttpResponse(status=200, _headers={"Forwarded": ""})
        result = _parse_forwarded_header_from_http_response(http_response)

        assert not result

    def test_parse_different_formats(self):
        http_response = _MockHttpResponse(status=200, _headers={"Forwarded": "for=\"192.0.2.43:47011\"  ; for= \"[2001:db8:cafe::17]:47011\" ; for=unknown; for=\"_gazonk\"; for=_hidden"},)
        result = _parse_forwarded_header_from_http_response(http_response)

        assert result.forwarded_for == ["192.0.2.43:47011", "[2001:db8:cafe::17]:47011", "unknown", "_gazonk", "_hidden"]

