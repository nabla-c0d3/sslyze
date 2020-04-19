from sslyze import __version__


class HttpRequestGenerator:

    HTTP_GET_FORMAT = (
        "GET {path} HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "User-Agent: {user_agent}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/52.0.2743.116 Safari/537.36 SSLyze/{0}".format(__version__.__version__)
    )

    @classmethod
    def get_request(cls, host: str, path: str = "/") -> bytes:
        return cls.HTTP_GET_FORMAT.format(host=host, path=path, user_agent=cls.DEFAULT_USER_AGENT).encode("utf-8")
