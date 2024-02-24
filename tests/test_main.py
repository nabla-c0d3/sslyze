import sys
from unittest import mock

import pytest

from sslyze import SslyzeOutputAsJson
from sslyze.__main__ import main


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
