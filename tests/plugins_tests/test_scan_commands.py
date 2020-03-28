from sslyze.plugins.scan_commands import ScanCommandsRepository


class TestScanCommands:
    def test_all_commands_are_implemented(self):
        for scan_command in ScanCommandsRepository.get_all_scan_commands():
            assert ScanCommandsRepository.get_implementation_cls(scan_command)
