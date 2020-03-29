
SSLyze
######

Release |version|

.. image:: https://pepy.tech/badge/sslyze
    :target: https://pepy.tech/project/sslyze

.. image:: https://img.shields.io/pypi/l/sslyze.svg
    :target: https://pypi.org/project/sslyze/

.. image:: https://img.shields.io/pypi/pyversions/sslyze.svg
    :target: https://pypi.org/project/sslyze/

SSLyze is a fast and powerful SSL/TLS scanning library.

It allows you to analyze the SSL/TLS configuration of a server by connecting to it, in order to detect various
issues (bad certificate, weak cipher suites, Heartbleed, ROBOT, TLS 1.3 support, etc.).

SSLyze can either be used as command line tool or as a Python library.

.. contents::
   :depth: 3

Key features
************

* Fully documented Python API in order to run scans and process the results directly from Python.
* Support for TLS 1.3 and early data (0-RTT) testing.
* Scans are automatically dispatched among multiple workers, making them very fast.
* Performance testing: session resumption and TLS tickets support.
* Security testing: weak cipher suites, insecure renegotiation, ROBOT, Heartbleed and more.
* Server certificate validation and revocation checking through OCSP stapling.
* Support for StartTLS handshakes on SMTP, XMPP, LDAP, POP, IMAP, RDP, PostGres and FTP.
* Scan results can be written to a JSON file for further processing.
* And much more!

Installation
************

To install SSLyze, simply run this simple command in your terminal of choice::

    $ pip install --upgrade setuptools
    $ pip install sslyze

For other options and more details, see:

.. toctree::
   :maxdepth: 2

   installation

Running scans with the CLI
**************************

The command line interface can be used to easily run server scans, and for example export results to JSON::

    $ python -m sslyze --regular www.google.com --json_out=results.json

A full description of the supported options is available via the help command::

    $ python -m sslyze -h

Runing scans with the Python API
********************************

The Python API gives full access to SSLyze's scanning engine in order to make it easy to implement SSL/TLS scanning as
part of a continuous security testing platform, and detect any misconfiguration across a range of public and/or internal
endpoints.

Basic example
=============

A simple example on how to run a scan follows:

.. literalinclude:: ../api_sample.py
    :pyobject: basic_example

The list of all the scan comands SSLyze can run against a server is available in the following section:

.. toctree::
   :maxdepth: 2

   available-scan-commands

Advanced usage
==============

Using the Python API to scan a server is a two-step process, described in more details the following sections:

.. toctree::
   :maxdepth: 3

   testing-connectivity
   running-scan-commands

Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
