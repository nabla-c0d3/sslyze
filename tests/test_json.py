import json
from dataclasses import asdict

import sslyze
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze.plugins.scan_commands import ScanCommand
from tests.factories import ServerScanResultFactory


class TestJsonEncoder:
    def test(self):
        # Given a completed scan for a server
        scan_results = {ScanCommand.TLS_COMPRESSION: CompressionScanResult(supports_compression=True)}
        scan_result = ServerScanResultFactory.create(scan_commands_results=scan_results)

        # When converting it into to JSON
        result_as_json = json.dumps(asdict(scan_result), cls=sslyze.JsonEncoder)

        # It succeeds
        assert result_as_json
        assert "supports_compression" in result_as_json
