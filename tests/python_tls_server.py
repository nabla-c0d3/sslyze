import socket
import ssl
from pathlib import Path
from threading import Thread

from tests.openssl_server import DEFAULT_SERVER_CERTIFICATE_PATH, DEFAULT_SERVER_KEY_PATH


class PythonTlsServer:
    """A basic TLS server built on Python's ssl module.

    Unlike the s_server binaries in tests.openssl_server, it runs on all platforms (including Windows). This was built because the s_server binaries can be buggy and unpredictable on Windows.
    """

    def __init__(
        self,
        *,
        server_certificate_path: Path = DEFAULT_SERVER_CERTIFICATE_PATH,
        server_key_path: Path = DEFAULT_SERVER_KEY_PATH,
    ) -> None:
        self.hostname = "localhost"
        self.ip_address = "127.0.0.1"
        self.port = 0  # Set when the server starts

        self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ssl_context.load_cert_chain(server_certificate_path, server_key_path)
        self._listening_socket: socket.socket | None = None
        self._accept_thread: Thread | None = None

    def __enter__(self) -> "PythonTlsServer":  # noqa: PYI034
        # Let the OS pick an available port
        self._listening_socket = socket.create_server((self.ip_address, 0))
        self.port = self._listening_socket.getsockname()[1]

        self._accept_thread = Thread(target=self._accept_connections, daemon=True)
        self._accept_thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        if self._listening_socket:
            self._listening_socket.close()
        if self._accept_thread:
            self._accept_thread.join(timeout=5)

    def _accept_connections(self) -> None:
        assert self._listening_socket
        while True:
            try:
                client_socket, _ = self._listening_socket.accept()
            except OSError:
                # The listening socket was closed
                return
            Thread(target=self._handle_connection, args=(client_socket,), daemon=True).start()

    def _handle_connection(self, client_socket: socket.socket) -> None:
        client_socket.settimeout(5)
        try:
            with self._ssl_context.wrap_socket(client_socket, server_side=True) as tls_socket:
                # Keep the connection open until the client closes it
                while tls_socket.recv(1024):
                    pass
        except (OSError, ssl.SSLError):
            # Most of the connections sent by SSLyze are expected to fail (unsupported cipher suites, etc.)
            pass
        finally:
            client_socket.close()
