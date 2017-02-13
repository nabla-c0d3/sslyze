.. sslyze documentation master file, created by
   sphinx-quickstart on Sun Jan 15 12:41:02 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

SSLyze Documentation
====================

This is the documentation for using SSLyze as a Python module. The Python API has changed multiple times in the past,
but should be now considered stable (as of version 1.0.0).

This module gives full access to SSLyze's SSL/TLS scanning engine, which can analyze the SSL configuration of a server
by connecting to it and detect various issues (bad certificates, dangerous cipher suites, lack of session resumption,
etc.). Using SSLyze as a Python module makes it easy to implement SSL/TLS scanning as part of continuous security
testing platform, and detect any misconfiguration across a range of public and/or internal endpoints.

At high-level, running SSL/TLS scans against a server is a two-step process, described in the following sections:

.. toctree::
   :maxdepth: 3

   testing-connectivity
   running-scan-commands
   available-scan-commands
   writing-a-plugin


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
