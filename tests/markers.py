import pytest

from tests.openssl_server import ModernOpenSslServer

can_only_run_on_linux_64 = pytest.mark.skipif(not ModernOpenSslServer.is_platform_supported(), 'Not on Linux 64')
