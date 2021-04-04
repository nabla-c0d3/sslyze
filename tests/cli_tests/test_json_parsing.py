from pathlib import Path

from sslyze import SslyzeOutputAsJson


class TestJsonParsing:
    def test(self):
        # Given the result of a scan saved as JSON output
        output_as_json_file = Path(__file__).parent / "sslyze_output.json"
        output_as_json = output_as_json_file.read_text()

        # When parsing the output
        # It succeeds
        parsed_output = SslyzeOutputAsJson.parse_raw(output_as_json)
        assert parsed_output

        assert 2 == len(parsed_output.server_scan_results)
        assert 2 == len(parsed_output.server_scan_results)
