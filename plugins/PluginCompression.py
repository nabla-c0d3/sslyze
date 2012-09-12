from xml.etree.ElementTree import Element
import socket
import time
import re

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, constants, \
    X509_V_CODES, SSL_CTX
from utils.SSLyzeSSLConnection import SSLyzeSSLConnection



class PluginCompression(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginCompression",
        description="Checks to see if the server supports SSL Compression")
    available_commands.add_command(
        command="compression",
        help="Enable the test for compression",
        dest=None)

    def process_task(self, target, command, args):
        output_format = '        {0:<25} {1}'

        ctSSL_initialize()

        ssl_ctx = SSL_CTX.SSL_CTX('tlsv1') # sslv23 hello will fail for specific servers such as post.craigslist.org
        ssl_connect = SSLyzeSSLConnection(self._shared_settings, target,ssl_ctx,
                                          hello_workaround=True)

        try: # Perform the SSL handshake
            ssl_connect.connect()
            compression_status = ssl_connect._ssl.get_current_compression()
        finally:
            ssl_connect.close()
            
           

        ev = False

        ctSSL_cleanup()

        # Text output
        cmd_title = 'Compression'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]

        txt_result.append(output_format.format("Compression Status:", compression_status))

        # XML output
        xml_el = Element('compresison', value = compression_status)

        xml_result = Element(self.__class__.__name__, command = command,
                             title = cmd_title)
        xml_result.append(xml_el)

        return PluginBase.PluginResult(txt_result, xml_result)

