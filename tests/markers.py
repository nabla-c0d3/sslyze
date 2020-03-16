import pytest

from tests.openssl_server import ModernOpenSslServer

can_only_run_on_linux_64 = pytest.mark.skipif(
    condition=not ModernOpenSslServer.is_platform_supported(), reason="The test suite it not being run on Linux 64"
)
