
Appendix: Available Scan Commands
*********************************

Every type of scan that SSLyze can run against a server (supported cippher suites, session renegotiation, etc.) is
represented by a `ScanCommand`, which is implemented using a plugin system. Each `ScanCommand` will return a
`ScanResult` when run against a server.

This page lists all the `ScanCommands` and corresponding `ScanResults` available in the current release of SSLyze.


Shared Attributes
=================

The `ScanResult` classes described in this section have specific attributes containing the result of a specific
`ScanCommand`, but also share two attributes.

.. module:: sslyze.plugins.plugin_base
.. autoclass:: PluginScanResult()


CertificateInfoPlugin
=====================

.. automodule:: sslyze.plugins.certificate_info_plugin

.. autoclass:: CertificateInfoScanCommand()
   :members: __init__
.. autoclass:: CertificateInfoScanResult()
.. autoclass:: CertificateChainDeploymentAnalyzer()
.. autoclass:: CertificateChainDeploymentAnalysisResult()


Additional helper classes
-------------------------

.. autoclass:: PathValidationResult()
.. autoclass:: PathValidationError()
.. autoclass:: OcspResponseStatusEnum()
   :members:
   :undoc-members:
.. autoclass:: SymantecDistrustTimelineEnum()
   :members:
   :undoc-members:

.. automodule:: sslyze.plugins.utils.trust_store.trust_store
.. autoclass:: TrustStore()

Updating the trust stores
-------------------------

.. automodule:: sslyze.plugins.utils.trust_store.trust_store_repository
.. autoclass:: TrustStoresRepository()
   :members: update_default

OpenSslCipherSuitesPlugin
=========================

.. automodule:: sslyze.plugins.openssl_cipher_suites_plugin

.. autoclass:: Sslv20ScanCommand()
.. autoclass:: Sslv30ScanCommand()
.. autoclass:: Tlsv10ScanCommand()
.. autoclass:: Tlsv11ScanCommand()
.. autoclass:: Tlsv12ScanCommand()
.. autoclass:: Tlsv13ScanCommand()
.. autoclass:: CipherSuiteScanResult()

Additional helper classes
-------------------------

.. autoclass:: AcceptedCipherSuite()
.. autoclass:: RejectedCipherSuite()
.. autoclass:: ErroredCipherSuite()


CompressionPlugin
=================

.. automodule:: sslyze.plugins.compression_plugin

.. autoclass:: CompressionScanCommand()
.. autoclass:: CompressionScanResult()


FallbackScsvPlugin
==================

.. automodule:: sslyze.plugins.fallback_scsv_plugin

.. autoclass:: FallbackScsvScanCommand()
.. autoclass:: FallbackScsvScanResult()


HeartbleedPlugin
================

.. automodule:: sslyze.plugins.heartbleed_plugin

.. autoclass:: HeartbleedScanCommand()
.. autoclass:: HeartbleedScanResult()


HttpHeadersScanPlugin
=====================

.. automodule:: sslyze.plugins.http_headers_plugin

.. autoclass:: HttpHeadersScanCommand()
.. autoclass:: HttpHeadersScanResult()

Additional helper classes
-------------------------

.. autoclass:: ParsedHstsHeader()
.. autoclass:: ParsedHpkpHeader()
.. autoclass:: ParsedExpectCtHeader()


OpenSslCcsInjectionPlugin
=========================

.. automodule:: sslyze.plugins.openssl_ccs_injection_plugin

.. autoclass:: OpenSslCcsInjectionScanCommand()
.. autoclass:: OpenSslCcsInjectionScanResult()


SessionRenegotiationPlugin
==========================

.. automodule:: sslyze.plugins.session_renegotiation_plugin

.. autoclass:: SessionRenegotiationScanCommand()
.. autoclass:: SessionRenegotiationScanResult()


SessionResumptionPlugin
=======================

.. automodule:: sslyze.plugins.session_resumption_plugin

.. autoclass:: SessionResumptionSupportScanCommand()
.. autoclass:: SessionResumptionSupportScanResult()

.. autoclass:: SessionResumptionRateScanCommand()
.. autoclass:: SessionResumptionRateScanResult()

RobotPlugin
===========

.. automodule:: sslyze.plugins.robot_plugin

.. autoclass:: RobotScanCommand()
.. autoclass:: RobotScanResultEnum()
   :members:
   :undoc-members:
.. autoclass:: RobotScanResult()


EarlyDataPlugin
===============

.. automodule:: sslyze.plugins.early_data_plugin

.. autoclass:: EarlyDataScanCommand()
.. autoclass:: EarlyDataScanResult()
