
SSLyze Python API
=================

Release |version|

This is the documentation for using SSLyze as a Python module.

Overview
--------

The Python API gives full access to SSLyze's SSL/TLS scanning engine, which can analyze the SSL configuration of a
server by connecting to it, and detect various issues (bad certificates, dangerous cipher suites, lack of session
resumption, etc.).

A simple example on how to run a scan follows:

.. literalinclude:: ../api_sample.py
   :pyobject: demo_synchronous_scanner

Using SSLyze as a Python module makes it easy to implement SSL/TLS scanning as part of continuous security
testing platform, and detect any misconfiguration across a range of public and/or internal endpoints.


User’s Guide
------------

At high-level, running SSL/TLS scans against a server is a two-step process, described in the following sections:

.. toctree::
   :maxdepth: 3

   testing-connectivity
   running-scan-commands


Available Scan Commands
-----------------------

The list of all the scan comands SSLyze can run against a server is available in the following section:

.. toctree::
   :maxdepth: 3

   available-scan-commands


Extending SSLyze
----------------

SSLyze is built using a plugin system, which makes it easy to add new capabilities to the tool:

.. toctree::
   :maxdepth: 3

   writing-a-plugin


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
