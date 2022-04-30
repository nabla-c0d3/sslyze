import shlex

import subprocess
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from platform import architecture
from sys import platform

import logging
import time
from threading import Thread
from typing import Optional, List, IO


class NotOnLinux64Error(EnvironmentError):
    """The embedded OpenSSL server is only available on Linux 64."""


class ClientAuthConfigEnum(Enum):
    """Whether the server asked for client authentication."""

    DISABLED = 1
    OPTIONAL = 2
    REQUIRED = 3


class _OpenSslServerIOManager:
    """Thread to log all output from s_server and reply to incoming connections."""

    def __init__(
        self, s_server_stdout: IO[bytes], s_server_stdin: IO[bytes], should_reply_to_http_requests: bool
    ) -> None:
        self._s_server_stdout = s_server_stdout
        self._s_server_stdin = s_server_stdin
        self._should_reply_to_http_requests = should_reply_to_http_requests
        self.is_server_ready = False

        def read_and_log_and_reply():
            while True:
                s_server_out = self._s_server_stdout.readline()
                if s_server_out:
                    logging.warning(f"s_server output: {s_server_out}")

                    if b"ACCEPT" in s_server_out:
                        # The s_server process is ready to receive connections
                        self.is_server_ready = True

                    if _OpenSslServer.HELLO_MSG in s_server_out:
                        # When receiving the special message, we want s_server to reply
                        self._s_server_stdin.write(b"Hey there")
                        self._s_server_stdin.flush()

                    if self._should_reply_to_http_requests:
                        if b"Connection: close\r\n" in s_server_out:
                            # We "Connection: close" to detect an HTTP request being sent and we return an HTTP response
                            self._s_server_stdin.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            self._s_server_stdin.flush()
                else:
                    break

        self.thread = Thread(target=read_and_log_and_reply, args=())
        self.thread.daemon = True
        self.thread.start()

    def close(self):
        pass
        # TODO(AD): This hangs on Linux; figure it out
        # self.s_server_stdout.close()
        # self.s_server_stdin.close()
        # self.thread.join()


_DEFAULT_SERVER_CERTIFICATE_PATH = Path(__file__).parent.absolute() / "server-rsa-cert.pem"
_DEFAULT_SERVER_KEY_PATH = Path(__file__).parent.absolute() / "server-rsa-key.pem"


class _OpenSslServer(ABC):
    """A wrapper around OpenSSL's s_server CLI."""

    _AVAILABLE_LOCAL_PORTS = set(range(8110, 8150))

    _S_SERVER_CMD = (
        "{openssl} s_server -cert {server_cert} -key {server_key} -accept {port}"
        ' -cipher "{cipher}" {verify_arg} {extra_args}'
    )

    # Client authentication - files generated using https://gist.github.com/nabla-c0d3/c2c5799a84a4867e5cbae42a5c43f89a
    _CLIENT_CA_PATH = Path(__file__).parent.absolute() / "client-ca.pem"

    # A special message clients can send to get a reply from s_server
    HELLO_MSG = b"Hello\r\n"

    @classmethod
    def get_client_certificate_path(cls) -> Path:
        return Path(__file__).parent.absolute() / "client-cert.pem"

    @classmethod
    def get_client_key_path(cls) -> Path:
        return Path(__file__).parent.absolute() / "client-key.pem"

    @classmethod
    @abstractmethod
    def get_openssl_path(cls) -> Path:
        pass

    @classmethod
    @abstractmethod
    def get_verify_argument(cls, client_auth_config: ClientAuthConfigEnum) -> str:
        pass

    @staticmethod
    def is_platform_supported() -> bool:
        if platform not in ["linux", "linux2"]:
            return False
        if architecture()[0] != "64bit":
            return False
        return True

    def __init__(
        self,
        *,
        server_certificate_path: Path,
        server_key_path: Path,
        client_auth_config: ClientAuthConfigEnum,
        should_enable_server_cipher_preference: bool,
        openssl_cipher_string: Optional[str],
        should_reply_to_http_requests: bool = True,
        extra_openssl_args: Optional[List[str]] = None,
    ) -> None:
        if not self.is_platform_supported():
            raise NotOnLinux64Error()

        final_extra_args = [] if extra_openssl_args is None else extra_openssl_args
        if should_enable_server_cipher_preference:
            final_extra_args.append("-serverpref")

        self.hostname = "localhost"
        self.ip_address = "127.0.0.1"
        self._server_certificate_path = server_certificate_path
        self._server_key_path = server_key_path
        self._should_reply_to_http_requests = should_reply_to_http_requests

        # Retrieve one of the available local ports; set.pop() is thread safe
        self.port = self._AVAILABLE_LOCAL_PORTS.pop()
        self._process = None
        self._server_io_manager = None

        self._command_line = self._S_SERVER_CMD.format(
            openssl=self.get_openssl_path(),
            server_key=self._server_key_path,
            server_cert=self._server_certificate_path,
            port=self.port,
            verify_arg=self.get_verify_argument(client_auth_config),
            extra_args=" ".join(final_extra_args) if extra_openssl_args else "",
            cipher=openssl_cipher_string if openssl_cipher_string else "DEFAULT",
        )

    def __enter__(self):
        logging.warning(f'Running s_server: "{self._command_line}"')
        args = shlex.split(self._command_line)
        try:
            self._process = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            self._server_io_manager = _OpenSslServerIOManager(
                self._process.stdout, self._process.stdin, self._should_reply_to_http_requests
            )

            # Block until s_server is ready to accept requests
            while not self._server_io_manager.is_server_ready:
                time.sleep(0.5)
                if self._process.poll() is not None:
                    # s_server has terminated early
                    raise RuntimeError("Could not start s_server")

        except Exception as e:
            logging.warning(f"Error while starting s_server: {e}")
            self._terminate_process()
            raise

        return self

    def __exit__(self, *args):
        logging.warning("Exiting s_server context")
        self._terminate_process()
        return False

    def _terminate_process(self) -> None:
        logging.warning("Shutting down s_server")
        if self._server_io_manager:
            self._server_io_manager.close()
        self._server_io_manager = None

        if self._process and self._process.poll() is None:
            self._process.terminate()
            self._process.wait()
        self._process = None

        # Free the port that was used; not thread safe but should be fine
        self._AVAILABLE_LOCAL_PORTS.add(self.port)


class LegacyOpenSslServer(_OpenSslServer):
    """A wrapper around the OpenSSL 1.0.0e s_server binary."""

    def __init__(
        self,
        *,
        server_certificate_path: Path = _DEFAULT_SERVER_CERTIFICATE_PATH,
        server_key_path: Path = _DEFAULT_SERVER_KEY_PATH,
        client_auth_config: ClientAuthConfigEnum = ClientAuthConfigEnum.DISABLED,
        should_enable_server_cipher_preference: bool = False,
        openssl_cipher_string: Optional[str] = None,
        require_server_name_indication_value: Optional[str] = None,
    ) -> None:
        extra_args = []
        if require_server_name_indication_value:
            # Have the server trigger a TLS alert when the client provides an SNI field that is not the supplied name
            extra_args = [
                f"-servername {require_server_name_indication_value}",
                "-servername_fatal",
                f"-cert2 {server_certificate_path}",
                f"-key2 {server_key_path}",
            ]

        super().__init__(
            client_auth_config=client_auth_config,
            openssl_cipher_string=openssl_cipher_string,
            extra_openssl_args=extra_args,
            should_enable_server_cipher_preference=should_enable_server_cipher_preference,
            server_certificate_path=server_certificate_path,
            server_key_path=server_key_path,
        )

    @classmethod
    def get_openssl_path(cls) -> Path:
        return Path(__file__).parent.absolute() / "openssl-1-0-0e-linux64"

    @classmethod
    def get_verify_argument(cls, client_auth_config: ClientAuthConfigEnum) -> str:
        options = {
            ClientAuthConfigEnum.DISABLED: "",
            ClientAuthConfigEnum.OPTIONAL: f"-verify {cls._CLIENT_CA_PATH}",
            ClientAuthConfigEnum.REQUIRED: f"-Verify {cls._CLIENT_CA_PATH}",
        }
        return options[client_auth_config]


class ModernOpenSslServer(_OpenSslServer):
    """A wrapper around the OpenSSL 1.1.1 s_server binary."""

    @classmethod
    def get_openssl_path(cls) -> Path:
        return Path(__file__).parent.absolute() / "openssl-1-1-1-linux64"

    @classmethod
    def get_verify_argument(cls, client_auth_config: ClientAuthConfigEnum) -> str:
        # The verify argument has subtly changed in OpenSSL 1.1.1
        options = {
            ClientAuthConfigEnum.DISABLED: "",
            ClientAuthConfigEnum.OPTIONAL: f"-verify 1 {cls._CLIENT_CA_PATH}",
            ClientAuthConfigEnum.REQUIRED: f"-Verify 1 {cls._CLIENT_CA_PATH}",
        }
        return options[client_auth_config]

    def __init__(
        self,
        *,
        server_certificate_path: Path = _DEFAULT_SERVER_CERTIFICATE_PATH,
        server_key_path: Path = _DEFAULT_SERVER_KEY_PATH,
        client_auth_config: ClientAuthConfigEnum = ClientAuthConfigEnum.DISABLED,
        should_enable_server_cipher_preference: bool = False,
        openssl_cipher_string: Optional[str] = None,
        should_reply_to_http_requests: bool = True,
        max_early_data: Optional[int] = None,
        groups: Optional[str] = None,
    ) -> None:
        extra_args = []
        if groups:
            extra_args.append(f"-groups {groups}")

        if max_early_data is not None:
            # Enable TLS 1.3 early data on the server
            extra_args += ["-early_data", f"-max_early_data {max_early_data}"]

        super().__init__(
            client_auth_config=client_auth_config,
            openssl_cipher_string=openssl_cipher_string,
            extra_openssl_args=extra_args,
            should_enable_server_cipher_preference=should_enable_server_cipher_preference,
            server_certificate_path=server_certificate_path,
            server_key_path=server_key_path,
            should_reply_to_http_requests=should_reply_to_http_requests,
        )
