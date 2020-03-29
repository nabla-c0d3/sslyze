
Step 2: Running Scan Commands Against a Server
##############################################

Every type of scan that SSLyze can run against a server (supported cipher suites, Heartbleed, etc.) is
represented by a ``ScanCommand``. Once a ``ScanCommand`` is run against a server, it returns a "result" object with
attributes containing the results of the scan command.

All the available ``ScanCommands`` and corresponding results are described in :doc:`available-scan-commands`.

The main class for running these commands is the ``Scanner`` class, which uses a pool of workers to run
``ScanCommand`` concurrently. It is very fast when scanning a large number of servers, and it has a rate-limiting
mechanism to avoid DOS-ing a single server against which multiple ``ScanCommand`` are run at the same time.


.. automodule:: sslyze
.. autoclass:: Scanner
   :members:

The commands can be queued by passing a ``ServerScanRequest`` to the ``Scanner.queue_scan()`` method.

.. autoclass:: ServerScanRequest

The results can later be retrieved using the ``Scanner.get_results()`` method, which returns an iterable of
``ServerScanResult``. Each result is returned as soon as the server scan was completed.

.. autoclass:: ServerScanResult
.. autoclass:: ScanCommandResultsDict
   :undoc-members:
   :members:

Basic Example
*************

A simple example on how to run some scan commands follows:

.. literalinclude:: ../api_sample.py
    :pyobject: basic_example


Advanced Usage
**************

The following script provides an example of running scan commands against multiple servers, and processing the results:

.. literalinclude:: ../api_sample.py
    :pyobject: main


Related classes
===============

.. autoclass:: ScanCommandErrorsDict
.. autoclass:: ScanCommandErrorReasonEnum
   :undoc-members:
   :members:
