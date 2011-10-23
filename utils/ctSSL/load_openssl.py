#-------------------------------------------------------------------------------
# Name:         load_openssl.py
# Purpose:      Helper module to find and load the OpenSSL libraries.
#               If succesful, the libraries can be imported in any module as
#               load_openssl.libcrypto and load_openssl.libssl.
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# Licence:      Licensed under the terms of the MIT License
#-------------------------------------------------------------------------------
#!/usr/bin/env python

import ctypes
from ctypes import c_ulong, c_char_p
import os
import sys


class ctSSLInitError(Exception):
    """
    Exception for any error happening while loading or initializing the OpenSSL
    library.
    """
    pass


# Find the OpenSSL DLLs, depending on the platform
if os.name == 'nt':
# On Windows, the proper DLLs are expected to be in the current folder.
    libcrypto_1_0_0 = '.\libeay32.dll' #Hopefully they are in the current folder
    libssl_1_0_0 = '.\ssleay32.dll'
    libcrypto_0_9_8 = 'libeay32' # Else, let the OS find them
    libssl_0_9_8 = 'ssleay32'

elif os.name == 'posix':
    # Warning: on Linux, not specifying the version of the lib inside its name
    # will make it go crazy
    if sys.platform == 'darwin': # MAC OS X
        libcrypto_1_0_0 = 'libcrypto.1.0.0.dylib'
        libssl_1_0_0 = 'libssl.1.0.0.dylib'
        libcrypto_0_9_8 = 'libcrypto.0.9.8.dylib'
        libssl_0_9_8 = 'libssl.0.9.8.dylib'

    elif sys.platform == 'cygwin':
        # Hopefully they are in the current folder
        libcrypto_1_0_0 = 'libeay32.dll'
        libssl_1_0_0 = 'ssleay32.dll'
        # Else, let the OS find them
        libcrypto_0_9_8 = 'libeay32'
        libssl_0_9_8 = 'ssleay32'

    else: # Any Linux
        libcrypto_1_0_0 = 'libcrypto.so.1.0.0'
        libssl_1_0_0 = 'libssl.so.1.0.0'
        libcrypto_0_9_8 = 'libcrypto.so.0.9.8'
        libssl_0_9_8 = 'libssl.so.0.9.8'

else:
    raise ctSSLInitError('OS not supported!')


# Load the OpenSSL DLLs
try: # We support OpenSSL 1.0.0
    libcrypto = ctypes.CDLL(libcrypto_1_0_0, use_errno=True,use_last_error=True)
    libssl = ctypes.CDLL(libssl_1_0_0, use_errno=True, use_last_error=True)
except OSError:
    try: # And OpenSSL 0.9.8
        libcrypto = \
            ctypes.CDLL(libcrypto_0_9_8, use_errno=True, use_last_error=True)
        libssl = ctypes.CDLL(libssl_0_9_8, use_errno=True, use_last_error=True)
    except OSError:
        raise ctSSLInitError('Could not load OpenSSL 1.0.0 or 0.9.8.')

# Store OpenSSL's version
libcrypto.SSLeay.restype = c_ulong
libcrypto.SSLeay_version.argtypes = [c_ulong]
libcrypto.SSLeay_version.restype = c_char_p
OpenSSL_version =  libcrypto.SSLeay()


