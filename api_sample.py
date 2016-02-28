#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

# Add ./lib to the path for importing nassl
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))

from sslyze.plugins_finder import PluginsFinder
from sslyze.plugins_process_pool import PluginsProcessPool
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
import sslyze.plugins.plugin_base



if __name__ == '__main__':
        
    # Setup the servers to scan and ensure they are reachable
    hostname = 'smtp.gmail.com'
    try:
        server_info = ServerConnectivityInfo(hostname=hostname, port=587,
                                             tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP)
        server_info.test_connectivity_to_server()
    except ServerConnectivityError as e:
        # Could not establish an SSL connection to the server
        raise RuntimeError('Error when connecting to {}: {}'.format(hostname, e.error_msg))


    # Get the list of available plugins
    sslyze_plugins = PluginsFinder()

    # Create a process pool to run scanning commands concurrently
    plugins_process_pool = PluginsProcessPool(sslyze_plugins)

    # Queue some scan commands; the commands are same as what is described in the SSLyze CLI --help text.
    print '\nQueuing some commands...'
    plugins_process_pool.queue_plugin_task(server_info, 'sslv3')
    plugins_process_pool.queue_plugin_task(server_info, 'reneg')
    plugins_process_pool.queue_plugin_task(server_info, 'certinfo_basic')

    # Process the results
    reneg_result = None
    print '\nProcessing results...'
    for plugin_result in plugins_process_pool.get_results():
        # Sometimes a plugin command can unexpectedly fail (as a bug); it is returned as a PluginRaisedExceptionResult
        if isinstance(plugin_result, sslyze.plugins.plugin_base.PluginRaisedExceptionResult):
            plugins_process_pool.emergency_shutdown()
            raise RuntimeError('Scan command failed: {}'.format(plugin_result.as_text()))

        # Each plugin result has attributes with the information you're looking for, specific to each plugin
        # All these attributes are documented within each plugin's module
        if plugin_result.plugin_command == 'sslv3':
            # Do something with the result
            print 'SSLV3 cipher suites'
            for cipher in plugin_result.accepted_cipher_list:
                print '    {}'.format(cipher.name)

        elif plugin_result.plugin_command == 'reneg':
            reneg_result = plugin_result
            print 'Client renegotiation: {}'.format(plugin_result.accepts_client_renegotiation)
            print 'Secure renegotiation: {}'.format(plugin_result.supports_secure_renegotiation)

        elif plugin_result.plugin_command == 'certinfo_basic':
            print 'Server Certificate CN: {}'.format(plugin_result.certificate_chain[0].as_dict['subject']['commonName'])


    # All plugin results also always expose two APIs:
    # What the SSLyze CLI would output to the console
    print '\nSSLyze text output'
    for line in reneg_result.as_text():
        print line
    print '\nSSLyze XML node'
    # The XML node for the SSLyze CLI XML output
    print reneg_result.as_xml()


    # You should use the process pool to make scans quick, but you can also call plugins directly
    from sslyze.plugins.openssl_cipher_suites_plugin import OpenSslCipherSuitesPlugin
    print '\nCalling a plugin directly...'
    plugin = OpenSslCipherSuitesPlugin()
    plugin_result = plugin.process_task(server_info, 'tlsv1')
    for cipher in plugin_result.accepted_cipher_list:
        print '    {}'.format(cipher.name)


