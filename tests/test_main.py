import io
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest import mock

import pytest

from sslyze import SslyzeOutputAsJson
from sslyze.__main__ import main
from sslyze.cli.command_line_parser import CommandLineParser, CommandLineParsingError
from sslyze.mozilla_tls_profile.tls_config_checker import TlsConfigurationEnum
from tests.python_tls_server import PythonTlsServer


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
        with mock.patch.object(sys, "argv", command_line):  # noqa: SIM117
            # And the CLI exited early because there is no actual server to scan
            with pytest.raises(SystemExit):
                main()

    def test_json_out_in_console(self, capsys):
        # Given a command line to launch the sslyze CLI and return results as JSON in the console
        command_line = ["sslyze", "--json_out=-", "--compression", "www.google.com"]

        # When running the CLI, it succeeds
        with mock.patch.object(sys, "argv", command_line), pytest.raises(SystemExit):
            main()

        # And the JSON output was printed to the console
        json_output = capsys.readouterr().out
        assert json_output

        # And the JSON output has the expected format
        parsed_output = SslyzeOutputAsJson.model_validate_json(json_output)
        assert parsed_output

    # Test for the crash in https://github.com/nabla-c0d3/sslyze/issues/724
    @pytest.mark.skipif(sys.platform != "win32", reason="only relevant on Windows")
    def test_console_output_with_non_ascii_certificate_name_on_windows(self):
        # Given a server with a certificate whose name contains characters that cp1252 can't encode
        certificates_path = Path(__file__).parent / "server_certificates" / "unicode-cn"
        with PythonTlsServer(
            server_certificate_path=certificates_path / "unicode-cn-self-signed-cert.pem",
            server_key_path=certificates_path / "unicode-cn-self-signed-key.pem",
        ) as server:
            #
            # And a command line to scan it and check it against Mozilla's TLS configuration
            command_line = [
                "sslyze",
                "--tls_config=intermediate",
                f"{server.hostname}:{server.port}{{{server.ip_address}}}",
            ]
            with mock.patch.object(sys, "argv", command_line):
                #
                # And stdout uses a legacy encoding - as is the case with the frozen Windows executable
                legacy_stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
                with mock.patch.object(sys, "stdout", legacy_stdout):  # noqa: SIM117
                    #
                    # When running the CLI, it does not crash with a UnicodeEncodeError;
                    with pytest.raises(SystemExit):
                        # A SystemExit is raised because the server does not comply with the expected TLS configuration
                        main()

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

    @pytest.mark.parametrize(
        ("tls_config_option", "expected_tls_config_enum"),
        [
            ("modern", TlsConfigurationEnum.MOZILLA_MODERN),
            ("intermediate", TlsConfigurationEnum.MOZILLA_INTERMEDIATE),
        ],
    )
    def test_command_line_has_tls_config(self, tls_config_option, expected_tls_config_enum):
        # Given a command line that specifies --tls_config
        command_line = ["sslyze", f"--tls_config={tls_config_option}", "www.example.com"]

        # When parsing it
        with mock.patch.object(sys, "argv", command_line):
            parsed_command_line = CommandLineParser("test").parse_command_line()

        # Then the corresponding TLS configuration is selected
        assert parsed_command_line.tls_config_to_check_against_as_enum == expected_tls_config_enum
        assert parsed_command_line.tls_config_to_check_against

    def test_command_line_has_tls_config_disabled(self):
        # Given a command line that disables the TLS configuration check
        command_line = ["sslyze", "--tls_config=disable", "www.example.com"]

        # When parsing it
        with mock.patch.object(sys, "argv", command_line):
            parsed_command_line = CommandLineParser("test").parse_command_line()

        # Then no TLS configuration is selected
        assert parsed_command_line.tls_config_to_check_against_as_enum is None
        assert parsed_command_line.tls_config_to_check_against is None

    @pytest.mark.parametrize("removed_option", ["--tls_config=old", "--mozilla_config=intermediate"])
    def test_command_line_has_removed_tls_config_option(self, removed_option):
        # Given a command line that uses an option removed in 7.0.0 (https://github.com/nabla-c0d3/sslyze/issues/725)
        command_line = ["sslyze", removed_option, "www.example.com"]

        # When parsing it, argparse rejects the option
        with mock.patch.object(sys, "argv", command_line):
            parser = CommandLineParser("test")
            with pytest.raises(SystemExit):
                parser.parse_command_line()

    def test_command_line_has_tls_config_and_custom_tls_config(self):
        # Given a command line that specifies both --tls_config and --custom_tls_config
        custom_config_path = Path(__file__).parent.parent / "custom_tls_config_example.json"
        command_line = ["sslyze", "--tls_config=modern", "--custom_tls_config", str(custom_config_path), "example.com"]

        # When parsing it, it fails
        with mock.patch.object(sys, "argv", command_line):
            parser = CommandLineParser("test")
            with pytest.raises(CommandLineParsingError, match="Cannot use --custom_tls_config and --tls_config"):
                parser.parse_command_line()
