#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

# Add ./lib to the path for importing nassl
import os
import sys
sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))

from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand, Sslv30ScanCommand

if __name__ == '__main__':
    # Setup the server to scan and ensure it is online/reachable
    hostname = 'smtp.gmail.com'
    try:
        server_info = ServerConnectivityInfo(hostname=hostname, port=587,
                                             tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP)
        server_info = ServerConnectivityInfo(hostname=hostname, port=587,
                                             tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP)
        server_info.test_connectivity_to_server()
    except ServerConnectivityError as e:
        # Could not establish an SSL connection to the server
        raise RuntimeError('Error when connecting to {}: {}'.format(hostname, e.error_msg))


    # Example 1: Run one scan command synchronously to list the server's TLS 1.0 cipher suites
    print('\nRunning one scan command synchronously...')
    synchronous_scanner = SynchronousScanner()
    command = Tlsv10ScanCommand()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    for cipher in scan_result.accepted_cipher_list:
        print('    {}'.format(cipher.name))


    # Example 2: Run multiple scan commands concurrently. It is of course much faster than the SynchronousScanner
    concurrent_scanner = ConcurrentScanner()

    # Queue some scan commands
    print('\nQueuing some commands...')
    concurrent_scanner.queue_scan_command(server_info, Sslv30ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, SessionRenegotiationScanCommand())
    concurrent_scanner.queue_scan_command(server_info, CertificateInfoScanCommand())

    # Process the results
    reneg_result = None
    print('\nProcessing results...')
    for scan_result in concurrent_scanner.get_results():
        # All scan results have the corresponding scan_command and server_info as an attribute
        print('\nReceived scan result for {} on host {}'.format(scan_result.scan_command.__class__.__name__,
                                                                 scan_result.server_info.hostname))

        # Sometimes a scan command can unexpectedly fail (as a bug); it is returned as a PluginRaisedExceptionResult
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            raise RuntimeError('Scan command failed: {}'.format(scan_result.as_text()))

        # Each scan result has attributes with the information yo're looking for, specific to each scan command
        # All these attributes are documented within each scan command's module
        if isinstance(scan_result.scan_command, Sslv30ScanCommand):
            # Do something with the result
            print('SSLV3 cipher suites')
            for cipher in scan_result.accepted_cipher_list:
                print('    {}'.format(cipher.name))

        elif isinstance(scan_result.scan_command, SessionRenegotiationScanCommand):
            reneg_result = scan_result
            print('Client renegotiation: {}'.format(scan_result.accepts_client_renegotiation))
            print('Secure renegotiation: {}'.format(scan_result.supports_secure_renegotiation))

        elif isinstance(scan_result.scan_command, CertificateInfoScanCommand):
            print('Server Certificate CN: {}'.format(
                scan_result.certificate_chain[0].as_dict['subject']['commonName']
            ))


    # All the scan command results also always expose two APIs
    # What the SSLyze CLI would output to the console
    print('\nSSLyze text output')
    for line in reneg_result.as_text():
        print(line)
    print('\nSSLyze XML node')
    # The XML node for the SSLyze CLI XML output
    print(reneg_result.as_xml())

