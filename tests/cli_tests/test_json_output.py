from datetime import datetime
from pathlib import Path

from sslyze.cli.json_output import SslyzeOutputAsJson, ServerScanResultAsJson
from sslyze.plugins.compression_plugin import CompressionScanResult
from sslyze import ScanCommandErrorReasonEnum, ServerScanStatusEnum, ScanCommandAttemptStatusEnum
from sslyze.scanner.models import CompressionScanAttempt
from tests.factories import (
    ServerScanResultFactory,
    TracebackExceptionFactory,
    AllScanCommandsAttemptsFactory,
)


class TestSslyzeOutputAsJson:
    def test(self):
        # Given a bunch of scan results
        all_server_scan_results = [ServerScanResultFactory.create() for _ in range(5)]

        # When converting them to JSON, it succeeds
        json_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.from_orm(result) for result in all_server_scan_results],
            date_scans_started=datetime.utcnow(),
            date_scans_completed=datetime.utcnow(),
        )
        json_output_as_str = json_output.json(sort_keys=True, indent=4, ensure_ascii=True)
        assert json_output_as_str

        # And it can be parsed again
        assert SslyzeOutputAsJson.parse_raw(json_output_as_str)

    def test_connectivity_test_failed(self):
        # Given a scan result where sslyze was unable to connect to the server
        server_scan_result = ServerScanResultFactory.create(scan_status=ServerScanStatusEnum.ERROR_NO_CONNECTIVITY)

        # When converting it to JSON, it succeeds
        json_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.from_orm(server_scan_result)],
            date_scans_started=datetime.utcnow(),
            date_scans_completed=datetime.utcnow(),
        )
        json_output_as_str = json_output.json(sort_keys=True, indent=4, ensure_ascii=True)
        assert json_output_as_str

        # And it can be parsed again
        assert SslyzeOutputAsJson.parse_raw(json_output_as_str)

    def test_server_scan_completed_scan_command(self):
        # Given a completed scan for a server where a scan command was run
        compression_attempt = CompressionScanAttempt(
            status=ScanCommandAttemptStatusEnum.COMPLETED,
            error_reason=None,
            error_trace=None,
            result=CompressionScanResult(supports_compression=True),
        )
        server_scan_result = ServerScanResultFactory.create(
            scan_result=AllScanCommandsAttemptsFactory.create({"tls_compression": compression_attempt})
        )

        # When converting it to JSON, it succeeds
        json_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.from_orm(server_scan_result)],
            date_scans_started=datetime.utcnow(),
            date_scans_completed=datetime.utcnow(),
        )
        json_output_as_str = json_output.json(sort_keys=True, indent=4, ensure_ascii=True)
        assert json_output_as_str
        assert "supports_compression" in json_output_as_str

        # And it can be parsed again
        assert SslyzeOutputAsJson.parse_raw(json_output_as_str)

    def test_server_scan_completed_but_scan_command_returned_error(self):
        # Given a completed scan for a server where a scan command was run
        error_trace = TracebackExceptionFactory.create()
        compression_attempt = CompressionScanAttempt(
            # And it triggered an error
            status=ScanCommandAttemptStatusEnum.ERROR,
            error_reason=ScanCommandErrorReasonEnum.BUG_IN_SSLYZE,
            error_trace=error_trace,
            result=None,
        )
        server_scan_result = ServerScanResultFactory.create(
            scan_result=AllScanCommandsAttemptsFactory.create({"tls_compression": compression_attempt})
        )

        # When converting it to JSON, it succeeds
        json_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.from_orm(server_scan_result)],
            date_scans_started=datetime.utcnow(),
            date_scans_completed=datetime.utcnow(),
        )
        json_output_as_str = json_output.json(sort_keys=True, indent=4, ensure_ascii=True)
        assert json_output_as_str
        assert error_trace.exc_type.__name__ in json_output_as_str

        # And it can be parsed again
        assert SslyzeOutputAsJson.parse_raw(json_output_as_str)

    def test_parse_json_output(self):
        # Given the result of a scan saved as JSON output
        output_as_json_file = Path(__file__).parent / "sslyze_output.json"
        output_as_json = output_as_json_file.read_text()

        # When parsing the output
        # It succeeds
        parsed_output = SslyzeOutputAsJson.parse_raw(output_as_json)
        assert parsed_output
        assert 3 == len(parsed_output.server_scan_results)
