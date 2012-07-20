SSLyze
======

Fast and full-featured SSL scanner:
* Compatible with SSL 2.0, 3.0 and TLS 1.0, 1.1 and 1.2
* Server certificate, cipher suites, session resumption and insecure renegotiation scanning
* Supports StartTLS with SMTP and XMPP
* Can tunnel traffic through an HTTPS proxy
* Supports client authentication
* Provides XML output

Usage
-----

### Prerequisites: 
	Python 2.6 or 2.7 and OpenSSL 0.9.8+.

### Sample command line:
	$ python sslyze.py --regular www.isecpartners.com:443 www.google.com

User manual available at https://github.com/iSECPartners/sslyze/wiki

License
--------
GPLv2 - See LICENSE.txt.
