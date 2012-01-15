#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         features_not_available.py
# Purpose:      Constants defined during ctSSL's initialization. 
#               Depending on the OpenSSL library that was loaded, specific 
#               features might be unavailable.
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------

SSL2_NOT_AVAIL =                        False # SSL2 support.
SSL_SECURE_RENEGOTIATION_NOT_AVAIL =    False # Secure renegotiation APIs
