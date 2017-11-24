from __future__ import absolute_import
from __future__ import unicode_literals

from typing import Text


class WorkaroundForTls12ForCipherSuites(object):
    """Helper to figure out which version of OpenSSL to use for a given TLS 1.2 cipher suite.

    The nassl module supports using either a legacy or a modern version of OpenSSL. When using TLS 1.2, specific cipher
    suites are only supported by one of the two implementation.
    """

    # Cipher suites that are only supported by the legacy OpenSSL
    _LEGACY_CIPHER_SUITES = {
        'EXP-EDH-DSS-DES-CBC-SHA', 'DH-RSA-AES128-GCM-SHA256', 'DH-RSA-CAMELLIA256-SHA', 'DH-RSA-AES128-SHA256',
        'ECDH-RSA-AES256-SHA', 'EXP-ADH-RC4-MD5', 'EDH-DSS-DES-CBC-SHA', 'ECDH-RSA-AES256-SHA384',
        'ECDH-ECDSA-NULL-SHA', 'DH-RSA-CAMELLIA128-SHA', 'EXP-ADH-DES-CBC-SHA', 'DH-DSS-AES128-GCM-SHA256',
        'ECDH-ECDSA-DES-CBC3-SHA', 'EXP-EDH-RSA-DES-CBC-SHA', 'DH-RSA-DES-CBC3-SHA', 'DH-DSS-DES-CBC3-SHA',
        'DH-DSS-AES128-SHA256', 'DH-DSS-DES-CBC-SHA', 'ECDH-ECDSA-AES256-SHA', 'DH-RSA-AES128-SHA',
        'DH-RSA-AES256-GCM-SHA384', 'ADH-DES-CBC-SHA', 'ECDH-ECDSA-AES128-SHA', 'ECDH-RSA-AES128-GCM-SHA256',
        'DH-DSS-AES128-SHA', 'ECDH-RSA-NULL-SHA', 'DH-DSS-CAMELLIA256-SHA', 'ECDH-ECDSA-AES256-SHA384',
        'EXP-RC2-CBC-MD5', 'DH-DSS-SEED-SHA', 'DH-DSS-AES256-GCM-SHA384', 'DH-DSS-CAMELLIA128-SHA',
        'EDH-RSA-DES-CBC-SHA', 'DES-CBC-SHA', 'DH-DSS-AES256-SHA256', 'ECDH-ECDSA-AES128-GCM-SHA256',
        'ECDH-RSA-DES-CBC3-SHA', 'ECDH-RSA-AES256-GCM-SHA384', 'ECDH-RSA-AES128-SHA256', 'DH-RSA-AES256-SHA',
        'ECDH-ECDSA-RC4-SHA', 'DH-RSA-AES256-SHA256', 'EDH-DSS-DES-CBC3-SHA', 'DH-DSS-AES256-SHA',
        'ECDH-ECDSA-AES128-SHA256', 'ECDH-ECDSA-AES256-GCM-SHA384', 'EXP-RC4-MD5', 'DH-RSA-SEED-SHA',
        'ECDH-RSA-RC4-SHA', 'EXP-DES-CBC-SHA', 'EDH-RSA-DES-CBC3-SHA', 'ECDH-RSA-AES128-SHA', 'DH-RSA-DES-CBC-SHA'
    }

    @classmethod
    def requires_legacy_openssl(cls, cipher_name):
        # type: (Text) -> bool
        return cipher_name in cls._LEGACY_CIPHER_SUITES
