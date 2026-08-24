import io
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile
from unittest import mock

import pytest

from sslyze import SslyzeOutputAsJson
from sslyze.__main__ import main
from sslyze.cli.command_line_parser import CommandLineParser, CommandLineParsingError
from sslyze.mozilla_tls_profile.tls_config_checker import TlsConfigurationEnum


class TestMainStdoutEncoding:
    def test_main_reconfigures_stdout_and_stderr_to_utf8(self):
        # Given stdout/stderr set up like a redirected console on a non-UTF-8 locale
        # (this is what a frozen Windows executable's stdout looks like)
        fake_stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        fake_stderr = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")

        # When running main(), even on a command line that fails argument parsing
        # and never reaches a scan
        with (
            mock.patch.object(sys, "argv", ["sslyze"]),
            mock.patch.object(sys, "stdout", fake_stdout),
            mock.patch.object(sys, "stderr", fake_stderr),
        ):
            main()

        # Then stdout/stderr were switched to UTF-8 with a non-crashing error handler
        assert fake_stdout.encoding.lower() == "utf-8"
        assert fake_stdout.errors == "backslashreplace"
        assert fake_stderr.encoding.lower() == "utf-8"
        assert fake_stderr.errors == "backslashreplace"

    def test_printing_non_cp1252_text_does_not_crash_after_main(self):
        # Given a stream that would raise UnicodeEncodeError for this text before the fix
        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        server_supplied_text = "Certificate subject CN=测试.example is not trusted"
        with pytest.raises(UnicodeEncodeError):
            print(server_supplied_text, file=stream)

        # When main() reconfigures a stream the same way it reconfigures sys.stdout/stderr
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")

        # Then printing the same server-supplied text no longer raises
        print(server_supplied_text, file=stream)


class TestMain:
    def test(self):
        # Given a command line to launch the sslyze CLI
        command_line = ["sslyze", "--quiet", "--compression", "www.google.com"]

        # When running the CLI, it succeeds
        with mock.patch.object(sys, "argv", command_line):
            main()

    def test_no_valid_server_strings(self):
        # Given a command line to launch the sslyze CLI, but the supplied server string is invalid
        command_line = ["sslyze", "--quiet", "--compression", "invalid.server.testests"]

        # When running the CLI, it succeeds
        with mock.patch.object(sys, "argv", command_line):
            # And the CLI exited early because there is no actual server to scan
            with pytest.raises(SystemExit):
                main()

    def test_json_out_in_console(self, capsys):
        # Given a command line to launch the sslyze CLI and return results as JSON in the console
        command_line = ["sslyze", "--json_out=-", "--compression", "www.google.com"]

        # When running the CLI, it succeeds
        with mock.patch.object(sys, "argv", command_line):
            with pytest.raises(SystemExit):
                main()

        # And the JSON output was printed to the console
        json_output = capsys.readouterr().out
        assert json_output

        # And the JSON output has the expected format
        parsed_output = SslyzeOutputAsJson.model_validate_json(json_output)
        assert parsed_output

    def test_command_line_has_valid_custom_tls_config_file(self):
        # Given a valid custom TLS configuration file
        custom_config_path = Path(__file__).parent.parent / "custom_tls_config_example.json"
        print(custom_config_path)
        assert custom_config_path.exists()

        # When parsing a command line that specifies --custom_tls_config
        command_line = ["sslyze", "--custom_tls_config", str(custom_config_path), "www.example.com"]
        with mock.patch.object(sys, "argv", command_line):
            parser = CommandLineParser("test")
            parsed_command_line = parser.parse_command_line()

        # Then it should parse successfully
        assert parsed_command_line.tls_config_to_check_against_as_enum == TlsConfigurationEnum.CUSTOM
        assert parsed_command_line.tls_config_to_check_against
        assert parsed_command_line.tls_config_to_check_against.tls_versions == {"TLSv1.2", "TLSv1.3"}

    def test_command_line_has_invalid_custom_tls_config_file(self):
        # Given TLS configuration that actually contains invalid JSON
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            temp_file.write('{"invalid": json syntax}')
            temp_file_path = temp_file.name

        # When parsing a command line that specifies --custom_tls_config
        command_line = ["sslyze", "--custom_tls_config", temp_file_path, "www.example.com"]
        with mock.patch.object(sys, "argv", command_line):
            parser = CommandLineParser("test")

            # Then the invalid JSON file is rejected
            with pytest.raises(CommandLineParsingError, match="Could not parse"):
                parser.parse_command_line()
