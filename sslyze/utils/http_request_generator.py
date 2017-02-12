import sslyze


class HttpRequestGenerator(object):

    HTTP_GET_FORMAT = u'GET / HTTP/1.1\r\n' \
                      u'Host: {host}\r\n' \
                      u'User-Agent: {user_agent}\r\n' \
                      u'Accept: */*\r\n' \
                      u'Connection: close\r\n\r\n'

    DEFAULT_USER_AGENT = u'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
                         u'Chrome/52.0.2743.116 Safari/537.36 SSLyze/{0}'.format(sslyze.__version__)

    @classmethod
    def get_request(cls, host, user_agent=None):
        final_user_agent = user_agent
        if final_user_agent is None:
            final_user_agent = cls.DEFAULT_USER_AGENT
        return cls.HTTP_GET_FORMAT.format(host=host, user_agent=final_user_agent)
