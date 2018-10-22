SSLyze
======

[![Build Status](https://travis-ci.org/nabla-c0d3/sslyze.svg?branch=master)](https://travis-ci.org/nabla-c0d3/sslyze)
[![PyPI version](https://badge.fury.io/py/SSLyze.svg)](https://badge.fury.io/py/SSLyze)
[![](https://images.microbadger.com/badges/image/nablac0d3/sslyze.svg)](https://microbadger.com/images/nablac0d3/sslyze)

Fast and powerful SSL/TLS server scanning library for Python 3.6+.


Description
-----------

SSLyze is a Python library and a CLI tool that can analyze the SSL configuration of a server by connecting to it. It is 
designed to be fast and comprehensive, and should help organizations and testers identify mis-configurations affecting 
their SSL/TLS servers.

Key features include:
* Fully [documented Python API](https://nabla-c0d3.github.io/sslyze/documentation/), in order to run scans and process the results directly from Python.
* **New: Support for TLS 1.3 and early data (0-RTT) testing.**
* Scans are automatically dispatched among multiple processes, making them very fast.
* Performance testing: session resumption and TLS tickets support.
* Security testing: weak cipher suites, insecure renegotiation, ROBOT, Heartbleed and more.
* Server certificate validation and revocation checking through OCSP stapling.
* Support for StartTLS handshakes on SMTP, XMPP, LDAP, POP, IMAP, RDP, PostGres and FTP.
* Scan results can be written to an XML or JSON file for further processing.
* And much more!


Usage as a CLI
--------------

SSLyze can be installed directly via pip:

    $ pip install --upgrade setuptools
    $ pip install --upgrade sslyze
    $ python -m sslyze --regular www.yahoo.com:443 www.google.com "[2607:f8b0:400a:807::2004]:443"

SSLyze has been tested on the following platforms: Debian 7 (32 and 64 bits), macOS High Sierra, and Windows 10
(Python 64 bits only).

Usage as a library
------------------

SSLyze exposes a Python API in order to run scans and process the results directly in Python; full documentation is
[available here][documentation].


Dev environment
---------------

If you want to setup a local environment where you can work on SSLyze, you will first need to install
[pipenv](https://docs.pipenv.org/). You can then initialize the environment using:

    $ cd sslyze
    $ pipenv install --dev
    $ pipenv shell

You can then run the test suite:

    $ invoke test

Windows executable
------------------

A Windows executable that does not require installing Python is available in the
[Releases page](https://github.com/nabla-c0d3/sslyze/releases) tab.


Docker
------

By default the image runs the `-h` flag:

```bash
docker run --rm -it nablac0d3/sslyze

Usage: sslyze [options] target1.com target2.com:443 target3.com:443{ip} etc...
 Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
```

This image was intended to be ran as an executable like so:

```bash
docker run --rm -it nablac0d3/sslyze --regular www.github.com:443
```

### Create utility from the image

Add the following line to your shell's rc file (e.g. ~/.bashrc):

```bash
alias 'sslyze'='docker run --rm -it nablac0d3/sslyze'
```

Now reload your shell defaults by running:

```bash
source ~/.bashrc
```

You can now execute the image like so:

 ```bash
$ sslyze
Usage: sslyze [options] target1.com target2.com:443 target3.com:443{ip} etc...
 Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
```

How does it work ?
------------------

SSLyze is all Python code but it uses an
[OpenSSL wrapper written in C called nassl](https://github.com/nabla-c0d3/nassl), which was specifically developed for
allowing SSLyze to access the low-level OpenSSL APIs needed to perform deep SSL testing.


Where do the trust stores come from?
------------------------------------

The trust stores (Mozilla, Microsoft, etc.) used by SSLyze for certificate validation are downloaded from the 
[Trust Stores Observatory](https://github.com/nabla-c0d3/trust_stores_observatory). 

The trust stores can be updated to the latest version, using either the CLI:

    $ python -m sslyze --update_trust_stores

or the Python API:
    
```python
from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository

TrustStoresRepository.update_default()
```

License
-------

Copyright (c) 2018 Alban Diquet

SSLyze is made available under the terms of the GNU Affero General Public License (AGPL). See LICENSE.txt for details and exceptions.

[documentation]: https://nabla-c0d3.github.io/sslyze/documentation
