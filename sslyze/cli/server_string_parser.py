import socket
from dataclasses import dataclass
from typing import Tuple, Optional


@dataclass(frozen=True)
class InvalidServerStringError(Exception):
    """Exception raised when SSLyze was unable to parse a hostname:port string supplied via the command line."""

    server_string: str
    error_message: str


class CommandLineServerStringParser:
    """Utility class to parse a 'host:port{ip}' string taken from the command line into a valid (host,ip, port) tuple.
    Supports IPV6 addresses.
    """

    SERVER_STRING_ERROR_BAD_PORT = "Not a valid host:port"

    @classmethod
    def parse_server_string(cls, server_str: str) -> Tuple[str, Optional[str], Optional[int]]:
        # Extract ip from target
        ip = None
        if "{" in server_str and "}" in server_str:
            raw_target = server_str.split("{")
            raw_ip = raw_target[1]

            ip = raw_ip.replace("}", "")

            # Clean the target
            server_str = raw_target[0]

        # Look for ipv6 hint in target
        if "[" in server_str:
            (host, port) = cls._parse_ipv6_server_string(server_str)
        else:
            # Look for ipv6 hint in the ip
            if ip is not None and "[" in ip:
                (ip, port) = cls._parse_ipv6_server_string(ip)

            # Fallback to ipv4
            (host, port) = cls._parse_ipv4_server_string(server_str)

        return host, ip, port

    @classmethod
    def _parse_ipv4_server_string(cls, server_str: str) -> Tuple[str, Optional[int]]:
        host = server_str
        port = None
        if ":" in server_str:
            host = (server_str.split(":"))[0]  # hostname or ipv4 address
            try:
                port = int((server_str.split(":"))[1])
            except ValueError:  # Port is not an int
                raise InvalidServerStringError(server_string=server_str, error_message=cls.SERVER_STRING_ERROR_BAD_PORT)

        return host, port

    @classmethod
    def _parse_ipv6_server_string(cls, server_str: str) -> Tuple[str, Optional[int]]:
        if not socket.has_ipv6:
            raise InvalidServerStringError(
                server_string=server_str, error_message="IPv6 is not supported on this platform"
            )

        port = None
        target_split = server_str.split("]")
        ipv6_addr = target_split[0].split("[")[1]
        if ":" in target_split[1]:  # port was specified
            try:
                port = int(target_split[1].rsplit(":")[1])
            except ValueError:  # Port is not an int
                raise InvalidServerStringError(server_string=server_str, error_message=cls.SERVER_STRING_ERROR_BAD_PORT)
        return ipv6_addr, port
