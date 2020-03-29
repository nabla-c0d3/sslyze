
Step 1: Testing Connectivity to a Server
########################################

.. module:: sslyze

.. contents::
   :depth: 3

Basic Example
*************

Before a server can be scanned, SSLyze must validate that it is able to connect to the server. This is done using
the ``ServerConnectivityTester`` class:

.. literalinclude:: ../api_sample.py
    :pyobject: basic_example_connectivity_testing

If the call to ``perform()`` is successful, it returns a ``ServerConnectivityInfo`` object that
can then be used for scanning the server.

This is described in :doc:`running-scan-commands`.

Advanced Usage
**************

When calling ``ServerConnectivityTester.perform()``, a ``ServerNetworkConfiguration`` can be optionally provided as the
second argument, in order to have more control on how SSLyze should connect to the server. This configuration object
allows for example to configure StarTLS or a client certificate SSL/TLS client authentication.

Main classes for connectivity testing
=====================================

.. autoclass:: ServerNetworkLocationViaDirectConnection
   :members: with_ip_address_lookup

.. autoclass:: ServerConnectivityTester
   :members: perform

.. autoclass:: ServerConnectivityInfo
   :undoc-members:
   :members:

Additional settings: StartTLS, SNI, etc.
========================================

.. autoclass:: ServerNetworkConfiguration
.. autoclass:: ProtocolWithOpportunisticTlsEnum
   :undoc-members:
   :members:

Running a scan through a proxy
==============================

.. autoclass:: ServerNetworkLocationViaHttpProxy
.. autoclass:: HttpProxySettings
   :members: from_url

Enabling SSL/TLS client authentication
======================================

.. autoclass:: ClientAuthenticationCredentials
.. autoclass:: OpenSslFileTypeEnum
   :undoc-members:
   :members:
