
SSLyze
######

Release |version|

.. image:: https://pepy.tech/badge/sslyze
    :target: https://pepy.tech/project/sslyze

.. image:: https://img.shields.io/pypi/l/sslyze.svg
    :target: https://pypi.org/project/sslyze/

.. image:: https://img.shields.io/pypi/pyversions/sslyze.svg
    :target: https://pypi.org/project/sslyze/

SSLyze is a fast and powerful SSL/TLS scanning tool and Python library.

SSLyze can analyze the SSL/TLS configuration of a server by connecting to it, in order to ensure that it uses strong
encryption settings (certificate, cipher suites, elliptic curves, etc.), and that it is not vulnerable to known TLS
attacks (Heartbleed, ROBOT, OpenSSL CCS injection, etc.).

.. contents::
   :depth: 3

Installation & Quick Start
**************************

Instructions on how to install and use SSLyze are available in
the `README <https://github.com/nabla-c0d3/sslyze#quick-start>`_.

Running scans using the Python API
**********************************

The Python API gives full access to SSLyze's scanning engine in order to make it easy to implement SSL/TLS scanning as
part of a continuous security testing platform, and detect any misconfiguration across a range of public and/or internal
endpoints.

.. toctree::
   :maxdepth: 2

   running-a-scan-in-python


Exporting and processing scan results in JSON
*********************************************

The result of SSLyze scans can be serialized to JSON for further processing. SSLyze also provides a helper class to
parse JSON scan results; it can be used to process the results of SSLyze scans in a separate Python program.

.. toctree::
   :maxdepth: 2

   json-output


Appendix: Scan Commands
***********************

.. toctree::
   :maxdepth: 2

   available-scan-commands

Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
