from sslyze import __version__


class HttpRequestGenerator:
    HTTP_GET_FORMAT = (
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
        f" Chrome/131.0.0.0 Safari/537.36 SSLyze/{__version__.__version__}"
    )

    @classmethod
    def get_request(cls, host: str, path: str = "/", user_agent: str | None = None) -> bytes:
        if not user_agent:
            user_agent = cls.DEFAULT_USER_AGENT
        return cls.HTTP_GET_FORMAT.format(host=host, path=path, user_agent=user_agent).encode("utf-8")
