SSLyze
======

Fast and full-featured SSL scanner.

Description
-----------

SSLyze is a Python tool that can analyze the SSL configuration of a server by
connecting to it. It is designed to be fast and comprehensive, and should help
organizations and testers identify misconfigurations affecting their SSL
servers.

 Key features include:
* SSL 2.0/3.0 and TLS 1.0/1.1/1.2 compatibility
* Performance testing: session resumption and TLS tickets support
* Security testing: weak cipher suites, insecure renegation, CRIME and THC-SSL DOS attacks
* Server certificate validation
* Support for StartTLS with SMTP and XMPP, and traffic tunneling through an HTTPS proxy
* Client certificate support for servers performing mutual authentication
* Scan results can be written to an XML file for further processing


Installation
------------

Supported platforms include Windows 7, Linux and OS X Mountain Lion, both 32
and 64 bits. SSLyze requires Python 2.6 or 2.7 and OpenSSL 0.9.8+.

### Linux / OS X
On Linux and OS X, SSLyze relies on the system's OpenSSL libraries.

### Windows
For Windows, specific packages that include the OpenSSL DLLs are provided.

### Installation Packages
Installation packages are available at: 
http://nabla-c0d3.blogspot.com/2013/01/sslyze-v06.html

Usage
-----

The user manual is available at: https://github.com/iSECPartners/sslyze/wiki

### Sample command line:
	$ python sslyze.py --regular www.isecpartners.com:443 www.google.com

See the test folder for additional examples.

License
--------

GPLv2 - See LICENSE.txt.
