import pytest

from sslyze.plugins.plugin_base import ServerScanRequest
from tests.factories import ServerConnectivityInfoFactory
from tests.mock_plugin import ScanCommandEnumForTests, MockPlugin1ExtraArguments


class TestServerScanRequest:

    def test_with_extra_arguments_but_no_corresponding_scan_command(self):
        # When trying to queue a scan for a server
        with pytest.raises(ValueError):
            ServerScanRequest(
                server_info=ServerConnectivityInfoFactory.create(),
                # With an extra argument for one command
                scan_commands_extra_arguments={
                    ScanCommandEnumForTests.MOCK_COMMAND_1: MockPlugin1ExtraArguments(extra_field="test")
                },
                # But that specific scan command was not queued
                scan_commands={ScanCommandEnumForTests.MOCK_COMMAND_2},
            )
            # It fails
