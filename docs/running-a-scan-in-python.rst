
Running a Scan in Python
########################

Overview
********

SSLyze's Python API can be used to run scans and process results in an automated fashion.

Every SSLyze class has typing annotations, which allows IDEs such as VS Code and PyCharms to auto-import modules
and auto-complete field names. Make sure to leverage this typing information as it will make it significantly easier
to use SSLyze's Python API.

To run a scan against a server, the scan can be described via the ``ServerScanRequest`` class, which contains
information about the server to scan(hostname, port, etc.)::

    try:
        all_scan_requests = [
            ServerScanRequest(server_location=ServerNetworkLocation(hostname="cloudflare.com")),
            ServerScanRequest(server_location=ServerNetworkLocation(hostname="google.com")),
        ]
    except ServerHostnameCouldNotBeResolved:
        # Handle bad input ie. invalid hostnames
        print("Error resolving the supplied hostnames")
        return

More details can optionally be supplied to the ``ServerScanRequest``, including:

* Server settings via the ``server_location`` argument, for example to use an HTTP proxy, or scan a specific IP address.
* Network settings via the ``network_configuration`` argument, for example to configure a client certificate, or scan a non-HTTP server.
* A specific of specific TLS checks to run (Heartbleed, cipher suites, etc.), via the `scan_commands` argument. By default, all the checks will be enabled.

Every type of TLS check that SSLyze can run against a server (supported cipher suites, Heartbleed, etc.) is
represented by a ``ScanCommand``. Once a ``ScanCommand`` is run against a server, it returns a "result" object with
attributes containing the results of the scan command.

All the available ``ScanCommands`` and corresponding results are described in :doc:`available-scan-commands`.

Then, to start the scan, pass the list of ``ServerScanRequest`` to ``Scanner.queue_scans()``::

    scanner = Scanner()
    scanner.queue_scans(all_scan_requests)

The ``Scanner`` class, uses a pool of workers to run the scans concurrently, but without DOS-ing the servers.

Lastly, the results can be retrieved using the ``Scanner.get_results()`` method, which returns an iterable of
``ServerScanResult``. Each result is returned as soon as the server scan was completed::


    for server_scan_result in scanner.get_results():
        print(f"\n\n****Results for {server_scan_result.server_location.hostname}****")

Full Example
************

A full example of running a scan on a couple servers follow:

.. literalinclude:: ../api_sample.py
    :pyobject: main


Classes for Starting a Scan
***************************

.. module:: sslyze
   :noindex:

.. autoclass:: ServerScanRequest

.. autoclass:: ServerNetworkLocation

.. autoclass:: Scanner

Additional settings: StartTLS, SNI, etc.
========================================

.. autoclass:: ServerNetworkConfiguration
.. autoclass:: ProtocolWithOpportunisticTlsEnum
   :undoc-members:
   :members:


Enabling SSL/TLS client authentication
======================================

.. autoclass:: ClientAuthenticationCredentials
.. autoclass:: OpenSslFileTypeEnum
   :undoc-members:
   :members:

Classes for Processing Scan Results
***********************************

.. autoclass:: ServerScanResult

.. autoclass:: ServerConnectivityStatusEnum

.. autoclass:: ServerScanStatusEnum

.. autoclass:: ServerTlsProbingResult

.. autoclass:: AllScanCommandsAttempts

.. autoclass:: ScanCommandAttempt

.. autoclass:: ScanCommandErrorReasonEnum
   :undoc-members:
   :members:



