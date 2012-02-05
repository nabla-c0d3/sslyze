#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         load_openssl.py
# Purpose:      Helper module to find and load the OpenSSL libraries.
#               If succesful, the libraries can be imported in any module as
#               load_openssl.libcrypto and load_openssl.libssl.
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------

import ctypes
from ctypes import c_ulong, c_char_p
from ctypes.util import find_library
import os
import sys


class ctSSLInitError(Exception):
    """
    Exception for any error happening while loading or initializing the OpenSSL
    library.
    """
    pass



def _load_openSSL_windows():
    try: # Hopefully the DLLs are in the current folder
        libcrypto = ctypes.CDLL('.\libeay32.dll', use_errno=True,use_last_error=True)
        libssl = ctypes.CDLL('.\ssleay32.dll', use_errno=True, use_last_error=True)
    except OSError:
        try: # Else let Windows find the DLLs.
            libcrypto = \
                ctypes.CDLL('libeay32', use_errno=True, use_last_error=True)
            libssl = ctypes.CDLL('ssleay32', use_errno=True, use_last_error=True)
        except OSError:
            raise ctSSLInitError('Could not load OpenSSL libraries.')
        
    return (libcrypto, libssl)


def _load_openSSL_linux_default():
    # On Linux we use find_library() to find the OpenSSL libraries
    libcrypto_path = find_library('crypto')
    libssl_path = find_library('ssl')
    try:
        libcrypto = ctypes.CDLL(libcrypto_path, use_errno=True,use_last_error=True)
        libssl = ctypes.CDLL(libssl_path, use_errno=True, use_last_error=True)
    except OSError:
        raise ctSSLInitError('Could not load OpenSSL libraries.')
    
    return (libcrypto, libssl)   


# Find the OpenSSL DLLs, depending on the platform
if os.name == 'nt':
    (libcrypto, libssl) = _load_openSSL_windows()

elif os.name == 'posix':
    if sys.platform == 'darwin': # MAC OS X
        (libcrypto, libssl) = _load_openSSL_linux_default()

    elif sys.platform == 'cygwin':
        (libcrypto, libssl) = _load_openSSL_windows()

    elif sys.platform == 'linux2': # Any Linux
        (libcrypto, libssl) = _load_openSSL_linux_default()

    elif sys.platform.startswith('freebsd'):
        (libcrypto, libssl) = _load_openSSL_linux_default()

    else: # ?
        (libcrypto, libssl) = _load_openSSL_linux_default()

else:
    raise ctSSLInitError('OS not supported!')


# Store OpenSSL's version
libcrypto.SSLeay.restype = c_ulong
libcrypto.SSLeay_version.argtypes = [c_ulong]
libcrypto.SSLeay_version.restype = c_char_p
OpenSSL_version =  libcrypto.SSLeay()
