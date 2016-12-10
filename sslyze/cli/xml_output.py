from sslyze.ssl_settings import TlsWrappedProtocolEnum
from xml.etree.ElementTree import Element


TLS_PROTOCOL_XML_TEXT = {
    TlsWrappedProtocolEnum.PLAIN_TLS: 'plainTls',
    TlsWrappedProtocolEnum.HTTPS: 'https',
    TlsWrappedProtocolEnum.STARTTLS_SMTP: 'startTlsSmtp',
    TlsWrappedProtocolEnum.STARTTLS_XMPP: 'startTlsXmpp',
    TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER: 'startTlsXmppServer',
    TlsWrappedProtocolEnum.STARTTLS_POP3: 'startTlsPop3',
    TlsWrappedProtocolEnum.STARTTLS_IMAP: 'startTlsImap',
    TlsWrappedProtocolEnum.STARTTLS_FTP: 'startTlsFtp',
    TlsWrappedProtocolEnum.STARTTLS_LDAP: 'startTlsLdap',
    TlsWrappedProtocolEnum.STARTTLS_RDP: 'startTlsRdp',
    TlsWrappedProtocolEnum.STARTTLS_POSTGRES: 'startTlsPostGres',
}



class XmlOutput(object):

    @classmethod
    def process_plugin_results(cls, server_info, result_list):
        target_attrib = {'host': server_info.hostname,
                         'ip': server_info.ip_address,
                         'port': str(server_info.port),
                         'tlsWrappedProtocol': TLS_PROTOCOL_XML_TEXT[server_info.tls_wrapped_protocol]
                         }
        if server_info.http_tunneling_settings:
            # Add proxy settings
            target_attrib['httpsTunnelHostname'] = server_info.http_tunneling_settings.hostname
            target_attrib['httpsTunnelPort'] = str(server_info.http_tunneling_settings.port)

        target_xml = Element('target', attrib=target_attrib)
        result_list.sort(key=lambda result: result)  # Sort results

        for plugin_result in result_list:
            target_xml.append(plugin_result.as_xml())

        return target_xml
