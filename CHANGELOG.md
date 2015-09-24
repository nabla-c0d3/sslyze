SSLyze Changelog
----------------

## v0.12
* Added the Google trust store for certificate validation and updated the Apple, Microsoft and Mozilla stores.
* A full (client) certificate chain can now be supplied when using client certificates.
* Added the ability to print the XML output to the console using --xml_out -.
* Various bug fixes including TLS errors that were mistakenly reported as network timeouts.
* Updated list of OIDs for identifying EV certificates.
* Updated OpenSSL to 1.0.2d, which fixes issues with certificate path validation when using --certinfo.


## v0.11
* Added support for Postgres StartTLS
* Added the --ca_file option for specifying a local trust store to validate the server's certificate
* Added the --quiet option to hide any text output when using --xml_out
* Improved the formatting of the XML output to make it easier to parse and more useful; this will break any tool that was processing the XML output from previous versions, but an XML Schema Definition is now available in SSLyze's root folder
* Bug fixes for EC certificates, HSTS, XMPP and LDAP
* Updated OpenSSL to 1.0.2a
* Updated Microsoft, Apple and Mozilla trust stores


## v0.10
* PluginOpenSSLCipherSuites now displays the size of the handshake's Diffie-Hellmann parameters
* SSLyze on Windows is now packaged as a single .exe file
* PluginCertInfo now displays the server's full certificate chain instead of its leaf certificate only, in both the console and XML results
* PluginHSTS now properly detects HSTS headers when receiving HTTP redirections
* New plugin to check if a server is affected by Chrome's deprecation of SHA1-signed certificates. See --chrome_sha1
* Clarified the console output of most plugins and checks
* Bug fixes for XML output and client certificate support
* Updated OpenSSL to 1.0.1i
* Updated Microsoft, Apple and Mozilla trust stores


## v0.9
* Experimental support for Heartbleed detection; see --heartbleed. Heartbleed detection has also been added to --regular scans.
* Capped the maximum number of concurrent connections to around 30 per server in order to avoid DOSing the scanned servers. Scans are slightly slower but a lot less aggressive, resulting in better scan results with less timeout and connection errors
* Support for Basic Authentication when tunneling scans through an HTTPS proxy with --https_tunnel
* Bug fixes for IPv6 and XMPP support
* Updated OpenSSL to 1.0.1g
* Updated the Apple, Microsoft, Mozilla and Java trust stores
* Cleaned up the text output of PluginOpenSSLCipherSuites


## v0.8
* Additional certificate chain validation using the Apple, Microsoft and Java trust stores in addition to Mozilla's
* Added support for StartTLS RDP; see --starttls=rdp
* Greatly improved the reliability and accuracy of scan results by adding an exponential backoff algorithm to retry failed network connections. This will especially impact scans against servers that stop properly answering after several concurrent connections have already been opened. The number of retry attempts can be controlled using --nb_retries
* Bug fixes including:
    * Better results when the server requested a client certificate but none was supplied
    * Clarified text and XML output
    * Better HTTP Strict Transport Security plugin
    * Fixed PluginCompression false negatives


## v0.7
* Complete rewrite of the OpenSSL wrapper as a C extension
   * SSLyze is now statically linked with the latest version of OpenSSL instead of using the system's (potentially outdated/broken) OpenSSL library
    * All of SSLyze's features are now available on all supported platforms (including SSL 2.0, TLS 1.1 and TLS 1.2)
    * Scans are slightly faster
    * Python 2.6 is no longer supported
* Support for StartTLS FTP, POP, IMAP, LDAP and "auto". See --starttls
* Support for OCSP Stapling. See --certinfo
* Other various improvements that results in SSLyze being more robust


## v0.6
* Added support for Server Name Indication; see --sni
* SSLyze now returns partial results when server requires mutual auth but no client certificate was provided
* Preliminary IPv6 support
* Various bug fixes and better support of client authentication and HTTPS tunneling


## v0.5
* XML output including full certificate parsing; see --xml_out
* The list of servers to scan can be provided using a text file; see --targets_in
* Improved certificate verification with hostname validation and EV certificates support
* Clarified output and lots of bug fixes
* OS X Mountain Lion is now officially supported
* Support for compression / CRIME testing


## v 0.4
* Support for OpenSSL 1.0.1 and TLS 1.1 and 1.2 scanning. See –tlsv1_1 and –tlsv1_2.
* Support for HTTP CONNECT proxies. See –https_tunnel.
* Support for StartTLS with SMTP and XMPP. See –starttls.
* Improved/clarified output.
* Various bug fixes.


## v 0.3
Initial public release.
