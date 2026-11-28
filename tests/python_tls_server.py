import socket
import ssl
from pathlib import Path
from threading import Thread

from tests.openssl_server import DEFAULT_SERVER_CERTIFICATE_PATH, DEFAULT_SERVER_KEY_PATH


class PythonTlsServer:
    """A basic TLS server built on Python's ssl module.

    Unlike the s_server binaries in tests.openssl_server, it runs on all platforms (including Windows). This was built to rely less on the s_server binaries for testing, as they can be buggy and unpredictable on Windows.
    """

    def __init__(
        self,
        *,
        server_certificate_path: Path = DEFAULT_SERVER_CERTIFICATE_PATH,
        server_key_path: Path = DEFAULT_SERVER_KEY_PATH,
        should_do_smtp_starttls: bool = False,
    ) -> None:
        self.hostname = "localhost"
        self.ip_address = "127.0.0.1"
        self.port = 0  # Set when the server starts

        self._should_do_smtp_starttls = should_do_smtp_starttls
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
            if self._should_do_smtp_starttls:
                self._do_smtp_starttls(client_socket)
            with self._ssl_context.wrap_socket(client_socket, server_side=True) as tls_socket:
                # Keep the connection open until the client closes it
                while tls_socket.recv(1024):
                    pass
        except (OSError, ssl.SSLError, _SmtpCommandRejectedError):
            # Most of the connections sent by SSLyze are expected to fail (unsupported cipher suites, etc.)
            pass
        finally:
            client_socket.close()

    def _do_smtp_starttls(self, client_socket: socket.socket) -> None:
        """Behave like a minimal SMTP server (RFC 5321 and RFC 3207) until the client sends STARTTLS.

        Only EHLO then STARTTLS is accepted; any other command gets a 5xx reply and the connection is closed.
        """
        # The client sends nothing after STARTTLS until it gets the 220 reply, so the reader cannot consume TLS data
        with client_socket.makefile("rb") as reader:
            client_socket.sendall(b"220 localhost ESMTP\r\n")

            command = reader.readline()
            if not command.upper().startswith(b"EHLO "):
                client_socket.sendall(b"503 5.5.1 Send EHLO first\r\n")
                raise _SmtpCommandRejectedError(command)
            client_socket.sendall(
                b"250-localhost\r\n250-PIPELINING\r\n250-SIZE 35882577\r\n250-8BITMIME\r\n250 STARTTLS\r\n"
            )

            command = reader.readline()
            if command.upper().rstrip(b"\r\n") != b"STARTTLS":
                client_socket.sendall(b"530 5.7.0 Must issue a STARTTLS command first\r\n")
                raise _SmtpCommandRejectedError(command)
            client_socket.sendall(b"220 2.0.0 Ready to start TLS\r\n")


class _SmtpCommandRejectedError(Exception):
    """The client sent an SMTP command that the server does not accept."""
