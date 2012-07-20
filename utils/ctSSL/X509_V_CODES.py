# 

#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         X509_V_CODES.py
# Purpose:      Certificate verification return codes. Taken from
#               http://www.openssl.org/docs/apps/verify.htm
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------


X509_V_CODES = {0 : "ok",
                2 : "unable to get issuer certificate",
                3 : "unable to get certificate CRL",
                4 : "unable to decrypt certificate's signature",
                5 : "unable to decrypt CRL's signature",
                6 : "unable to decode issuer public key",
                7 : "certificate signature failure",
                8 : "CRL signature failure",
                9 : "certificate is not yet valid",
                10 : "certificate has expired",
                11 : "CRL is not yet valid",
                12 : "CRL has expired",
                13 : "format error in certificate's notBefore field",
                14 : "format error in certificate's notAfter field",
                15 : "format error in CRL's lastUpdate field",
                16 : "format error in CRL's nextUpdate field",
                17 : "out of memory",
                18 : "self signed certificate",
                19 : "self signed certificate in certificate chain",
                20 : "unable to get local issuer certificate",
                21 : "unable to verify the first certificate",
                22 : "certificate chain too long",
                23 : "certificate revoked",
                24 : "invalid CA certificate",
                25 : "path length constraint exceeded",
                26 : "unsupported certificate purpose",
                27 : "certificate not trusted",
                28 : "certificate rejected",
                29 : "subject issuer mismatch",
                30 : "authority and subject key identifier mismatch",
                31 : "authority and issuer serial number mismatch",
                32 : "key usage does not include certificate signing",
                50 : "application verification failure"}