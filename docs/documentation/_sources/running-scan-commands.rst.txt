.. sslyze documentation master file, created by
   sphinx-quickstart on Sun Jan 15 12:41:02 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Step 2: Running Scan Commands Against a Server
**********************************************

Every type of scan that SSLyze can run against a server (supported cipher suites, session renegotiation, etc.) is
represented by a `ScanCommand`.

Once a `ScanCommand` is run against a server, it returns a `ScanResult` which is an object with attributes containing
the results of the scan. The list of attributes and what they mean depends on what kind of scan was run (ie. which
`ScanCommand`).

All the available `ScanCommands` and corresponding `ScanResults` are described in :doc:`available-scan-commands`.

As explained in :doc:`testing-connectivity`, a properly initialized `ServerConnectivityInfo` is needed before the
corresponding server can be scanned. Then, SSLyze can run `ScanCommands` against this server either:

* Sequentially using the `SynchronousScanner` class.
* Concurrently using the `ConcurrentScanner` class; this class is slightly more complex to use, but is also a lot faster when running a several `ScanCommand` and/or scanning multiple servers.


Running Commands Sequentially
=============================

Basic example
-------------

The SynchronousScanner class can be used to run `ScanCommands` against a server::

    # Run one scan command to list the server's TLS 1.0 cipher suites
    server_info = ServerConnectivityInfo(hostname=u'www.google.com')
    server_info.test_connectivity_to_server()
    command = Tlsv10ScanCommand()

    synchronous_scanner = SynchronousScanner()
    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    for cipher in scan_result.accepted_cipher_list:
        print(u'    {}'.format(cipher.name))



The SynchronousScanner class
----------------------------

.. automodule:: sslyze.synchronous_scanner
.. autoclass:: SynchronousScanner()
   :members: __init__, run_scan_command


Running Commands Concurrently
=============================

Basic example
-------------

The `ConcurrentScanner` uses a pool of processes to run `ScanCommands` concurrently. It is very fast when scanning a
large number of servers, and it has a dispatching mechanism to avoid DOS-ing a single server against which multiple
`ScanCommand` are run at the same time.

The commands can be queued using the `queue_scan_command()` method, and the results can later be retrieved using the
`get_results()` method::

    server_info = ServerConnectivityInfo(hostname=u'www.google.com')
    server_info.test_connectivity_to_server()

    concurrent_scanner = ConcurrentScanner()

    # Queue some scan commands
    concurrent_scanner.queue_scan_command(server_info, Sslv30ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, SessionRenegotiationScanCommand())
    concurrent_scanner.queue_scan_command(server_info, CertificateInfoScanCommand())

    # Process the results
    reneg_result = None
    for plugin_result in concurrent_scanner.get_results():
        # Sometimes a plugin command can unexpectedly fail (as a bug); it is returned as a PluginRaisedExceptionResult
        if isinstance(plugin_result, PluginRaisedExceptionScanResult):
            print(u'Scan command failed: {}'.format(plugin_result.as_text()))

        # Each plugin result has attributes with the information you're looking for, specific to each plugin
        # All these attributes are documented within each plugin's module
        if isinstance(plugin_result.scan_command, Sslv30ScanCommand):
            # Do something with the result
            print(u'SSLV3 cipher suites')
            for cipher in plugin_result.accepted_cipher_list:
                print(u'    {}'.format(cipher.name))

        elif isinstance(plugin_result.scan_command, SessionRenegotiationScanCommand):
            reneg_result = plugin_result
            print(u'Client renegotiation: {}'.format(plugin_result.accepts_client_renegotiation))
            print(u'Secure renegotiation: {}'.format(plugin_result.supports_secure_renegotiation))

        elif isinstance(plugin_result.scan_command, CertificateInfoScanCommand):
            print(u'Server Certificate CN: {}'.format(
                plugin_result.certificate_chain[0].as_dict[u'subject'][u'commonName']
            ))


The ConcurrentScanner class
---------------------------

.. automodule:: sslyze.concurrent_scanner
.. autoclass:: ConcurrentScanner()
   :members: __init__, queue_scan_command, get_results
.. autoclass:: PluginRaisedExceptionScanResult()

