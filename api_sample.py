
# Add ./lib to the path for importing nassl
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))

from sslyze.plugins_finder import PluginsFinder
from sslyze.plugins_process_pool import PluginsProcessPool
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum

# Setup the servers to scan and ensure they are reachable
try:
    server_info = ServerConnectivityInfo(hostname='smtp.gmail.com', port=587,
                                         tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP)
    server_info.test_connectivity_to_server()
except ServerConnectivityError as e:
    # Could not establish an SSL connection to the server
    raise RuntimeError('Error when connecting to {}: {}'.format(server_info.hostname, e.error_msg))

# Call a plugin directly
from sslyze.plugins.openssl_cipher_suites_plugin import OpenSslCipherSuitesPlugin

plugin = OpenSslCipherSuitesPlugin()
result = plugin.process_task(server_info, 'sslv3')
print result

# Get available plugins
sslyze_plugins = PluginsFinder()

# Send commands to process pool
plugins_process_pool = PluginsProcessPool(sslyze_plugins)
plugins_process_pool.queue_plugin_task(server_info, 'sslv2')
plugins_process_pool.queue_plugin_task(server_info, 'sslv3')
plugins_process_pool.queue_plugin_task(server_info, 'reneg')

# Process results
# All results have the initial command and server_info
for server_info, plugin_command, plugin_result in plugins_process_pool.get_results():

    # Each result contains fields with the information you're looking for, specific to each plugin
    if plugin_result.plugin_command == 'sslv3':
        for cipher in plugin_result.accepted_cipher_list:
            # Do something...
            print cipher.name


    # All results also always expose two APIs

    # What the SSLyze CLI would output to the console
    for line in plugin_result.as_text():
        print line

    # The XML node for the SSLyze CLI XML output
    print plugin_result.as_xml()


# Show internal results of Openssl or text or xml

# Otherwise call plugins directly