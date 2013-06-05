from xml.etree.ElementTree import Element
import socket

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup

class PluginHSTS(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginHSTS",
        description="Prints out the HSTS header details")
    available_commands.add_command(
        command="hsts",
        help="Help text for HSTS",
        dest=None)

    def process_task(self, target, command, args):

        output_format = '        {0:<25} {1}'

        ctSSL_initialize()
        ssl_connect = self._create_ssl_connection(target)

        header = None

        #try: # Perform the SSL handshake
        ssl_connect.connect()
        ssl_connect.request("HEAD", "/", headers={"Connection": "close"})
        http_response = ssl_connect.getresponse()
        header = http_response.getheader('Strict-Transport-Security', None)

        ctSSL_cleanup()

        # Text output
        cmd_title = 'HSTS'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        txt_result.append(output_format.format("Strict-Transport-Security header:", header))

        # XML output
        xml_hsts_attr = {'header_found': str(header != None)}
        if header:
            xml_hsts_attr['header'] = header
        xml_hsts = Element('hsts', attrib = xml_hsts_attr)
        
        xml_result = Element(self.__class__.__name__, command = command,
                             title = cmd_title)
        xml_result.append(xml_hsts)

        return PluginBase.PluginResult(txt_result, xml_result)

