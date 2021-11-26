
SSLyze
######

Release |version|

.. image:: https://pepy.tech/badge/sslyze
    :target: https://pepy.tech/project/sslyze

.. image:: https://img.shields.io/pypi/l/sslyze.svg
    :target: https://pypi.org/project/sslyze/

.. image:: https://img.shields.io/pypi/pyversions/sslyze.svg
    :target: https://pypi.org/project/sslyze/

SSLyze is a fast and powerful SSL/TLS scanning tool and Python library.

SSLyze can analyze the SSL/TLS configuration of a server by connecting to it, in order to ensure that it uses strong
encryption settings (certificate, cipher suites, elliptic curves, etc.), and that it is not vulnerable to known TLS
attacks (Heartbleed, ROBOT, OpenSSL CCS injection, etc.).

.. contents::
   :depth: 3

Key features
************

* Focus on speed and reliability: SSLyze is a battle-tested tool that is used to reliably scan hundreds of thousands of servers every day.
* Easy to operationalize: SSLyze can be directly run from CI/CD, in order to continuously check a server against Mozilla's recommended TLS configuration.
* Fully documented Python API to run scans directly from any Python application, such as a function deployed to AWS Lambda.
* Support for scanning non-HTTP servers including SMTP, XMPP, LDAP, POP, IMAP, RDP, Postgres and FTP servers.
* Results of a scan can easily be saved to a JSON file for later processing.
* And much more!

Installation
************

To install SSLyze, simply run this simple command in your terminal of choice::

    $ pip install --upgrade pip setuptools wheel
    $ pip install --upgrade sslyze

For other options and more details, see:

.. toctree::
   :maxdepth: 2

   installation

Running scans with the CLI
**************************

The command line interface can be used to easily run server scans, and for example export results to JSON::

    $ python -m sslyze www.google.com --json_out=results.json

A full description of the supported options is available via the help command::

    $ python -m sslyze -h

Running scans from CI/CD
************************


By default, SSLyze will check the server's scan results against Mozilla's recommended `"intermediate" TLS
configuration <https://wiki.mozilla.org/Security/Server_Side_TLS>`_, and will return a non-zero exit code if the server
is not compliant::

    $ python -m sslyze mozilla.com

    Checking results against Mozilla's "intermediate" configuration. See https://ssl-config.mozilla.org/ for more details.

    mozilla.com:443: OK - Compliant.

The Mozilla configuration to check against can be configured via `--mozilla-config={old, intermediate, modern}`::

    $ python -m sslyze --mozilla-config=modern mozilla.com

    Checking results against Mozilla's "modern" configuration. See https://ssl-config.mozilla.org/ for more details.

    mozilla.com:443: FAILED - Not compliant.
        * certificate_types: Deployed certificate types are {'rsa'}, should have at least one of {'ecdsa'}.
        * certificate_signatures: Deployed certificate signatures are {'sha256WithRSAEncryption'}, should have at least one of {'ecdsa-with-SHA512', 'ecdsa-with-SHA256', 'ecdsa-with-SHA384'}.
        * tls_versions: TLS versions {'TLSv1.2'} are supported, but should be rejected.
        * ciphers: Cipher suites {'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'} are supported, but should be rejected.

This can be used to easily run an SSLyze scan as a CI/CD step.

Running scans with the Python API
*********************************

The Python API gives full access to SSLyze's scanning engine in order to make it easy to implement SSL/TLS scanning as
part of a continuous security testing platform, and detect any misconfiguration across a range of public and/or internal
endpoints.

.. toctree::
   :maxdepth: 2

   running-a-scan-in-python


Exporting and processing scan results in JSON
*********************************************

The result of SSLyze scans can be serialized to JSON for further processing. SSLyze also provides a helper class to
parse JSON scan results; it can be used to process the results of SSLyze scans in a separate Python program.

.. toctree::
   :maxdepth: 2

   json-output


Appendix: Scan Commands
***********************

.. toctree::
   :maxdepth: 2

   available-scan-commands

Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
