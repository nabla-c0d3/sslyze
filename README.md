SSLyze
======

[![Build Status](https://travis-ci.org/nabla-c0d3/sslyze.svg?branch=master)](https://travis-ci.org/nabla-c0d3/sslyze)
[![Downloads](https://pepy.tech/badge/sslyze)](https://pepy.tech/badge/sslyze)
[![PyPI version](https://img.shields.io/pypi/v/sslyze.svg)](https://pypi.org/project/sslyze/)
[![Python version](https://img.shields.io/pypi/pyversions/sslyze.svg)](https://pypi.org/project/sslyze/)

SSLyze is a fast and powerful SSL/TLS scanning library.

It allows you to analyze the SSL/TLS configuration of a server by connecting to it, in order to detect various
issues (bad certificate, weak cipher suites, Heartbleed, ROBOT, TLS 1.3 support, etc.).

SSLyze can either be used as command line tool or as a Python library.

Key features
------------

* Fully [documented Python API](https://nabla-c0d3.github.io/sslyze/documentation/), in order to run scans and process 
the results directly from Python.
* Support for TLS 1.3 and early data (0-RTT) testing.
* Scans are automatically dispatched among multiple workers, making them very fast.
* Performance testing: session resumption and TLS tickets support.
* Security testing: weak cipher suites, insecure renegotiation, ROBOT, Heartbleed and more.
* Server certificate validation and revocation checking through OCSP stapling.
* Support for StartTLS handshakes on SMTP, XMPP, LDAP, POP, IMAP, RDP, PostGres and FTP.
* Scan results can be written to a JSON file for further processing.
* And much more!

Quick start
-----------

SSLyze can be installed directly via pip:

    $ pip install --upgrade setuptools
    $ pip install --upgrade sslyze
    $ python -m sslyze --regular www.yahoo.com:443 www.google.com "[2607:f8b0:400a:807::2004]:443"

Documentation
-------------

Documentation is [available here][documentation].

License
-------

Copyright (c) 2020 Alban Diquet

SSLyze is made available under the terms of the GNU Affero General Public License (AGPL). See LICENSE.txt for details and exceptions.

[documentation]: https://nabla-c0d3.github.io/sslyze/documentation
