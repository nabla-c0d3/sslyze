SSLyze
======

Fast and full-featured SSL scanner. Continuation of https://github.com/iSECPartners/sslyze.


Description
-----------

SSLyze is a Python tool that can analyze the SSL configuration of a server by
connecting to it. It is designed to be fast and comprehensive, and should help
organizations and testers identify misconfigurations affecting their SSL
servers.

Key features include:
* Multi-processed and multi-threaded scanning (it's fast)
* SSL 2.0/3.0 and TLS 1.0/1.1/1.2 compatibility
* Performance testing: session resumption and TLS tickets support
* Security testing: weak cipher suites, insecure renegotiation, CRIME, Heartbleed and more
* Server certificate validation and revocation checking through OCSP stapling
* Support for StartTLS handshakes on SMTP, XMPP, LDAP, POP, IMAP, RDP and FTP
* Support for client certificates when scanning servers that perform mutual authentication
* XML output to further process the scan results
* And much more !


Installation
------------

SSLyze requires Python 2.7; the supported platforms are Windows 7 32/64 bits,
Linux 32/64 bits and OS X 64 bits.

SSLyze is statically linked with OpenSSL. For this reason, the easiest
way to run SSLyze is to download one the pre-compiled packages available in
the GitHub releases section for this project, at
https://github.com/nabla-c0d3/sslyze/releases.


Usage
-----

### Command line options

The following command will provide the list of available command line options:
	$ python sslyze.py -h


### Sample command line:

	$ python sslyze.py --regular www.isecpartners.com:443 www.google.com

See the test folder for additional examples.


Build / nassl
-------------

SSLyze is all Python code but since version 0.7, it uses a custom OpenSSL
wrapper written in C called nassl. The pre-compiled packages for SSLyze
contain a compiled version of this wrapper in sslyze/nassl. If you want to
clone the SSLyze repo, you will have to get a compiled version of nassl from
one of the SSLyze packages and copy it to sslyze-master/nassl, in order to get
SSLyze to run.

The source code for nassl is hosted at https://github.com/nabla-c0d3/nassl.


Py2exe Build
------------

SSLyze can be packaged as a Windows executable by running the following command:

    $ python.exe setup_py2exe.py py2exe


Where do the trust stores come from?
------------------------------------

The Mozilla, Microsoft, Apple and Java trust stores are downloaded using the 
following tool: https://github.com/nabla-c0d3/catt/blob/master/sslyze.md.


License
--------

GPLv2 - See LICENSE.txt.
