from pathlib import Path

import pytest

from sslyze import (
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommandsExtraArguments,
    CertificateInfoExtraArgument,
    ScanCommand,
)
from sslyze.scanner.models import get_scan_command_attempt_cls


class TestServerScanRequest:
    def test_default_values(self):
        # Given just a server location
        server_location = ServerNetworkLocation(hostname="www.google.com", port=443, ip_address="1.1.1.1")

        # When creating a scan request with the minimum set of arguments, it succeeds
        scan_request = ServerScanRequest(server_location=server_location)

        # And default values were generated
        assert scan_request.uuid
        assert scan_request.network_configuration
        assert len(scan_request.scan_commands) > 5

    def test_extra_arguments_but_no_corresponding_scan_command(self):
        # Given a server location
        server_location = ServerNetworkLocation(hostname="www.google.com", port=443, ip_address="1.1.1.1")

        # When trying to queue a scan for a server
        with pytest.raises(ValueError):
            ServerScanRequest(
                server_location=server_location,
                # With an extra argument for one command
                scan_commands_extra_arguments=ScanCommandsExtraArguments(
                    certificate_info=CertificateInfoExtraArgument(custom_ca_file=Path(__file__))
                ),
                # But that specific scan command was not queued
                scan_commands={ScanCommand.ROBOT},
            )
            # It fails


class TestScanCommandAttempt:
    def test_get_scan_command_attempt_cls(self):
        for scan_command in ScanCommand:
            assert get_scan_command_attempt_cls(scan_command)
