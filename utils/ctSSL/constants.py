#-------------------------------------------------------------------------------
# Name:         constants.py
# Purpose:      Some OpenSSL constants used by ctSSL.
#               I had to redefine them because they are defined using C macros
#               in OpenSSL.
#               TODO: Clean.
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------
#!/usr/bin/env python

import features_not_available

# SSL_CTX_set_verify()
SSL_VERIFY_NONE	=                   0x00
SSL_VERIFY_PEER	=                   0x01
SSL_VERIFY_FAIL_IF_NO_PEER_CERT	=   0x02
SSL_VERIFY_CLIENT_ONCE =            0x04


SSL_OP_NO_TICKET = 0x00004000L # No TLS Session Tickets
SSL_SESS_CACHE_OFF = 0 # No Session Resumption

if not features_not_available.SSL_SECURE_RENEGOTIATION_NOT_AVAIL:
    SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 0x00040000L


# Certificate and private key format
SSL_FILETYPE_PEM =  1
SSL_FILETYPE_ASN1 = 2