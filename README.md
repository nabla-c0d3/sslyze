SSLyze
======

![Run Tests](https://github.com/nabla-c0d3/sslyze/workflows/Run%20Tests/badge.svg)
[![Downloads](https://pepy.tech/badge/sslyze/month)](https://pepy.tech/project/sslyze)
[![PyPI version](https://img.shields.io/pypi/v/sslyze.svg)](https://pypi.org/project/sslyze/)
[![Python version](https://img.shields.io/pypi/pyversions/sslyze.svg)](https://pypi.org/project/sslyze/)

SSLyze is a fast and powerful SSL/TLS scanning tool and Python library.

SSLyze can analyze the SSL/TLS configuration of a server by connecting to it, in order to ensure that it uses strong
encryption settings (certificate, cipher suites, elliptic curves, etc.), and that it is not vulnerable to known TLS
attacks (Heartbleed, ROBOT, OpenSSL CCS injection, etc.).

Key features
------------

* Focus on speed and reliability: SSLyze is a battle-tested tool that is used to reliably scan **hundreds of thousands**
of servers every day.
* Easy to operationalize: SSLyze can be directly run from CI/CD, in order to continuously check a server against 
Mozilla's recommended TLS configurations.
* Fully documented [Python API](https://nabla-c0d3.github.io/sslyze/documentation/) to run scans directly from any
Python application, such as a function deployed to AWS Lambda.
* Support for scanning non-HTTP servers including SMTP, XMPP, LDAP, POP, IMAP, RDP, Postgres and FTP servers.
* Results of a scan can easily be saved to a JSON file for later processing.
* And much more!

Quick start
-----------

On Windows, Linux (x86 or x64) and macOS, SSLyze can be installed directly via pip:

```
$ pip install --upgrade pip setuptools wheel
$ pip install --upgrade sslyze
$ python -m sslyze www.yahoo.com www.google.com "[2607:f8b0:400a:807::2004]:443"
```

It can also be used via Docker:

```
$ docker run --rm -it nablac0d3/sslyze:6.1.0 www.google.com
```

Lastly, a pre-compiled Windows executable can be downloaded from [the Releases
page](https://github.com/nabla-c0d3/sslyze/releases).

Python API Documentation
------------------------

A sample script describing how to use the SSLyze's Python API is available at [./api_sample.py](https://github.com/nabla-c0d3/sslyze/blob/release/api_sample.py).

Full documentation for SSLyze's Python API is [available here][documentation].

Usage as a CI/CD step
---------------------

By default, SSLyze will check the server's scan results against Mozilla's recommended ["intermediate" TLS
configuration](https://wiki.mozilla.org/Security/Server_Side_TLS), and will return a non-zero exit code if the server
is not compliant. 

```
$ python -m sslyze mozilla.com
```
```
Checking results against Mozilla's "intermediate" configuration. See https://ssl-config.mozilla.org/ for more details.

mozilla.com:443: OK - Compliant.
```

The Mozilla configuration to check against can be configured via `--mozilla_config={old, intermediate, modern}`:
```
$ python -m sslyze --mozilla_config=modern mozilla.com
```
```
Checking results against Mozilla's "modern" configuration. See https://ssl-config.mozilla.org/ for more details.

mozilla.com:443: FAILED - Not compliant.
    * certificate_types: Deployed certificate types are {'rsa'}, should have at least one of {'ecdsa'}.
    * certificate_signatures: Deployed certificate signatures are {'sha256WithRSAEncryption'}, should have at least one of {'ecdsa-with-SHA512', 'ecdsa-with-SHA256', 'ecdsa-with-SHA384'}.
    * tls_versions: TLS versions {'TLSv1.2'} are supported, but should be rejected.
    * ciphers: Cipher suites {'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'} are supported, but should be rejected.
```

Alternatively, you can check against your own custom TLS configuration by providing a JSON file that follows Mozilla's TLS configuration format:

```
$ python -m sslyze --custom_tls_config custom_tls_config_example.json mozilla.com
```
```
Checking results against custom TLS configuration.

mozilla.com:443: OK - Compliant.
```

See `custom_tls_config_example.json` for an example a custom TLS configuration that can be used by SSLyze.

**This functionality can be used to easily run an SSLyze scan as a CI/CD step in order to ensure TLS compliance.**

Development environment
-----------------------

To setup a development environment:

```
$ pip install --upgrade pip setuptools wheel
$ pip install -e . 
$ pip install -r requirements-dev.txt
```

The tests can then be run using:

```
$ invoke test
```

License
-------

Copyright (c) 2026 Alban Diquet

SSLyze is made available under the terms of the GNU Affero General Public License (AGPL). See LICENSE.txt for details and exceptions.

[documentation]: https://nabla-c0d3.github.io/sslyze/documentation
