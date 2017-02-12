.. sslyze documentation master file, created by
   sphinx=quickstart on Sun Jan 15 12:41:02 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Available Scan Commands
***********************

Every type of scan that SSLyze can run against a server (supported cippher suites, session renegotiation, etc.) is
represented by a `ScanCommand`, which is implemented using a plugin system. Each `ScanCommand` will return a
`ScanResult` when run against a server.

This page lists all the `ScanCommands` and corresponding `ScanResults` available in the current release of SSLyze.


CertificateInfoPlugin
=====================

.. automodule:: sslyze.plugins.certificate_info_plugin

CertificateInfoScanCommand
--------------------------

.. autoclass:: CertificateInfoScanCommand()
   :members: __init__
.. autoclass:: CertificateInfoScanResult()


Additional helper classes
-------------------------

.. autoclass:: PathValidationResult()
.. autoclass:: PathValidationError()
.. automodule:: sslyze.plugins.utils.certificate
.. autoclass:: Certificate()
.. automodule:: sslyze.plugins.utils.trust_store.trust_store
.. autoclass:: TrustStore()


OpenSslCipherSuitesPlugin
=========================

.. automodule:: sslyze.plugins.openssl_cipher_suites_plugin


CipherSuiteScanCommands
-----------------------

.. autoclass:: Sslv20ScanCommand()
.. autoclass:: Sslv30ScanCommand()
.. autoclass:: Tlsv10ScanCommand()
.. autoclass:: Tlsv11ScanCommand()
.. autoclass:: Tlsv12ScanCommand()
.. autoclass:: Tlsv12ScanCommand()
.. autoclass:: CipherSuiteScanResult()

Additional helper classes
-------------------------

.. autoclass:: AcceptedCipherSuite()
.. autoclass:: RejectedCipherSuite()
.. autoclass:: ErroredCipherSuite()


CompressionPlugin
=================

.. automodule:: sslyze.plugins.compression_plugin


CompressionScanCommand
----------------------

.. autoclass:: CompressionScanCommand()
.. autoclass:: CompressionScanResult()


FallbackScsvPlugin
==================

.. automodule:: sslyze.plugins.fallback_scsv_plugin


FallbackScsvScanCommand
-----------------------

.. autoclass:: FallbackScsvScanCommand()
.. autoclass:: FallbackScsvScanResult()


HeartbleedPlugin
================

.. automodule:: sslyze.plugins.heartbleed_plugin


HeartbleedScanCommand
---------------------

.. autoclass:: HeartbleedScanCommand()
.. autoclass:: HeartbleedScanResult()


HttpHeadersScanPlugin
=====================

.. automodule:: sslyze.plugins.http_headers_plugin

HttpHeadersScanCommand
----------------------

.. autoclass:: HttpHeadersScanCommand()
.. autoclass:: HttpHeadersScanResult()

Additional helper classes
-------------------------

.. autoclass:: ParsedHstsHeader()
.. autoclass:: ParsedHpkpHeader()


OpenSslCcsInjectionPlugin
=========================

.. automodule:: sslyze.plugins.openssl_ccs_injection_plugin

OpenSslCcsInjectionScanCommand
------------------------------


.. autoclass:: OpenSslCcsInjectionScanCommand()
.. autoclass:: OpenSslCcsInjectionScanResult()


SessionRenegotiationPlugin
==========================

.. automodule:: sslyze.plugins.session_renegotiation_plugin

SessionRenegotiationScanCommand
-------------------------------

.. autoclass:: SessionRenegotiationScanCommand()
.. autoclass:: SessionRenegotiationScanResult()


SessionResumptionPlugin
=======================

.. automodule:: sslyze.plugins.session_resumption_plugin

SessionResumptionSupportScanCommand
-----------------------------------

.. autoclass:: SessionResumptionSupportScanCommand()
.. autoclass:: SessionResumptionSupportScanResult()

SessionResumptionRateScanCommand
--------------------------------

.. autoclass:: SessionResumptionRateScanCommand()
.. autoclass:: SessionResumptionRateScanResult()
