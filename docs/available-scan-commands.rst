
Appendix: Scan Commands
#######################

Every type of scan that SSLyze can run against a server (supported cipher suites, session renegotiation, etc.) is
represented by a ``ScanCommand``, which, when run against a server, will return a specific result.

This page lists all the ``ScanCommand`` and their corresponding results available in the current release of SSLyze.

For an example on how to run a ``ScanCommand``, see :doc:`/running-scan-commands`.

.. contents::
   :depth: 2

The following scan commands are available in the current version of SSLyze:

.. module:: sslyze
.. autoclass:: ScanCommand
   :members:
   :undoc-members:

The next sections describe the result class that corresponds to each scan command.

Certificate Information
***********************

**ScanCommand.CERTIFICATE_INFO**: Retrieve and analyze a server's certificate(s) to verify its validity.

Optional arguments
==================

.. autoclass:: CertificateInfoExtraArguments

Result class
============

.. autoclass:: CertificateInfoScanResult
.. autoclass:: CertificateDeploymentAnalysisResult
.. autoclass:: PathValidationResult
.. autoclass:: TrustStore
.. autoclass:: OcspResponse
.. autoclass:: OcspResponseStatusEnum
   :members:
   :undoc-members:

Cipher Suites
*************

**ScanCommand.SSL_2_0_CIPHER_SUITES**: Test a server for SSL 2.0 support.
**ScanCommand.SSL_3_0_CIPHER_SUITES**: Test a server for SSL 3.0 support.
**ScanCommand.TLS_1_0_CIPHER_SUITES**: Test a server for TLS 1.0 support.
**ScanCommand.TLS_1_1_CIPHER_SUITES**: Test a server for TLS 1.1 support.
**ScanCommand.TLS_1_2_CIPHER_SUITES**: Test a server for TLS 1.2 support.
**ScanCommand.TLS_1_3_CIPHER_SUITES**: Test a server for TLS 1.3 support.

Result class
============

.. autoclass:: CipherSuitesScanResult
.. autoclass:: CipherSuiteRejectedByServer
.. autoclass:: CipherSuiteAcceptedByServer
.. autoclass:: EphemeralKeyInfo
.. autoclass:: CipherSuite
.. autoclass:: TlsVersionEnum
   :members:
   :undoc-members:

ROBOT
*****

**ScanCommand.ROBOT**: Test a server for the ROBOT vulnerability.

Result class
============

.. autoclass:: RobotScanResult
.. autoclass:: RobotScanResultEnum
   :members:
   :undoc-members:

Session Resumption Support
**************************

**ScanCommand.SESSION_RESUMPTION**: Test a server for session resumption support using session IDs and TLS tickets.

Result class
============

.. autoclass:: SessionResumptionSupportScanResult

Session Resumption Rate
***********************

**ScanCommand.SESSION_RESUMPTION_RATE**: Measure a server's session resumption rate when attempting 100 resumptions using session IDs.

Result class
============

.. autoclass:: SessionResumptionRateScanResult

CRIME
*****

**ScanCommand.TLS_COMPRESSION**: Test a server for TLS compression support, which can be leveraged to perform a CRIME attack.

Result class
============

.. autoclass:: CompressionScanResult

TLS 1.3 Early Data
******************

**ScanCommand.TLS_1_3_EARLY_DATA**: Test the server(s) for TLS 1.3 early data support.

Result class
============

.. autoclass:: EarlyDataScanResult

Downgrade Prevention
********************

**ScanCommand.TLS_FALLBACK_SCSV**: Test a server for the TLS_FALLBACK_SCSV mechanism to prevent downgrade attacks.

Result class
============

.. autoclass:: FallbackScsvScanResult

Heartbleed
**********

**ScanCommand.HEARTBLEED**: Test a server for the OpenSSL Heartbleed vulnerability.

Result class
============

.. autoclass:: HeartbleedScanResult

HTTP Security Headers
*********************

**ScanCommand.HTTP_HEADERS**: Test a server for the presence of security-related HTTP headers.

Result class
============

.. autoclass:: HttpHeadersScanResult
.. autoclass:: StrictTransportSecurityHeader
.. autoclass:: PublicKeyPinsHeader
.. autoclass:: ExpectCtHeader

OpenSSL CCS Injection
*********************

**ScanCommand.OPENSSL_CCS_INJECTION**: Test a server for the OpenSSL CCS Injection vulnerability (CVE-2014-0224).

Result class
============

.. autoclass:: OpenSslCcsInjectionScanResult

Insecure Renegotiation
**********************

**ScanCommand.SESSION_RENEGOTIATION**: Test a server for for insecure TLS renegotiation and client-initiated renegotiation.

Result class
============

.. autoclass:: SessionRenegotiationScanResult
