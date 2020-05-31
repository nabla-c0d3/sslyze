
Step 2: Running Scan Commands Against a Server
##############################################

Every type of scan that SSLyze can run against a server (supported cipher suites, Heartbleed, etc.) is
represented by a ``ScanCommand``. Once a ``ScanCommand`` is run against a server, it returns a "result" object with
attributes containing the results of the scan command.

All the available ``ScanCommands`` and corresponding results are described in :doc:`available-scan-commands`.


Basic Example
*************

The main class for running these commands is the ``Scanner`` class, which uses a pool of workers to run
``ScanCommand`` concurrently. It is very fast when scanning a large number of servers, and it has a rate-limiting
mechanism to avoid DOS-ing a single server against which multiple ``ScanCommand`` are run at the same time.

The commands can be queued by passing a ``ServerScanRequest`` to the ``Scanner.queue_scan()`` method.

The results can later be retrieved using the ``Scanner.get_results()`` method, which returns an iterable of
``ServerScanResult``. Each result is returned as soon as the server scan was completed.

A simple example on how to run some scan commands follows:

.. literalinclude:: ../api_sample.py
    :pyobject: basic_example


Advanced Usage
**************

The following script provides an example of running scan commands against multiple servers, and processing the results:

.. literalinclude:: ../api_sample.py
    :pyobject: main


Related Classes
***************

.. automodule:: sslyze
.. autoclass:: Scanner
   :members:

.. autoclass:: ServerScanRequest

.. autoclass:: ServerScanResult
.. autoclass:: ScanCommandResultsDict
   :undoc-members:
   :members:

.. autoclass:: ScanCommandErrorsDict
.. autoclass:: ScanCommandErrorReasonEnum
   :undoc-members:
   :members:


Exporting to JSON
*****************

A ``ServerScanResult`` can be serialized to JSON using SSLyze's special ``JsonEncoder``.

.. autoclass:: JsonEncoder
