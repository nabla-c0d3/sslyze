#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         __init__.py
# Purpose:      Initialize and cleanup functions for ctSSL.
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------

from ctypes import c_ulong, c_int, CFUNCTYPE, c_char_p, c_void_p
from load_openssl import libssl, libcrypto, ctSSLInitError
import SSL, BIO, SSL_CTX, errors, SSL_SESSION, X509
import features_not_available

openSSL_threading = False


def ctSSL_initialize(multithreading=False, zlib=False):
    """
    Initialize ctSSL's ctypes bindings, and OpenSSL libraries and error
    strings. Should always be called before any other ctSSL function.
    
    @type multithreading: boolean
    @param multithreading: Initialize OpenSSL multithreading support. 
    TODO: This actually doesn't do anything ATM.
    
    @type zlib: boolean
    @param zlib: Initialize support for Zlib compression.
    
    """
    # Initialize multithreading
    multithreading=False    # TODO: Clean start. Disabled for now, causes issues
                            # Might not be required ?
    if multithreading:
        openSSL_threading_init()
        openSSL_threading = True

        
    # Initialize libraries and error strings
    libssl.SSL_library_init()
    libssl.SSL_load_error_strings()
    if libcrypto.RAND_status() != 1:
        raise ctSSLInitError('OpenSSL PRNG not seeded with enough data.')

    # Tell ctypes the arguments and return types for every C function that is exposed
    BIO.init_BIO_functions()
    SSL_CTX.init_SSL_CTX_functions()
    SSL.init_SSL_functions()
    SSL_SESSION.init_SSL_SESSION_functions()
    X509.init_X509_functions()
    errors.init_ERR_functions()

    if zlib: # Enable Zlib compression. Can only be done globally.
        try:
            libcrypto.COMP_zlib.argtypes = []
            libcrypto.COMP_zlib.restype = c_void_p
    
            libssl.SSL_COMP_add_compression_method.argtypes = [c_int, c_void_p]
            libssl.SSL_COMP_add_compression_method.restype = c_int

            zlib_comp_p = libcrypto.COMP_zlib()
            has_zlib = libssl.SSL_COMP_add_compression_method(1, zlib_comp_p)
        
        except AttributeError: # OpenSSL is super old and COMP_XX() is not defined ?
            raise errors.ctSSLFeatureNotAvailable("Could not enable Zlib compression: not supported by the version of the OpenSSL library that was loaded ?")
        
        except: # TODO: Check for common errors here and add meaningful error message
            raise
            
        if has_zlib != 0:
            raise errors.ctSSLFeatureNotAvailable("Could not enable Zlib compression: OpenSSL was not built with Zlib support ?")
        
        features_not_available.ZLIB_NOT_AVAIL = False



def ctSSL_cleanup():
    libcrypto.EVP_cleanup()
    libcrypto.ERR_free_strings()

    # Multithreading cleanup
    if openSSL_threading:
        libcrypto.ERR_remove_state()
        libcrypto.CRYPTO_set_id_callback(None)
        libcrypto.CRYPTO_set_locking_callback(None)
        openSSL_crypto_lock_list = []


# MULTITHREADING SUPPORT
import thread

CRYPTO_LOCK =       0x01
openSSL_crypto_lock_list = []
OPENSSL_CRYPTO_NUM_LOCKS = 0


def openSSL_threading_locking_callback(mode, type, file, line):
    if (mode & CRYPTO_LOCK) :
        openSSL_crypto_lock_list[int(type)].acquire()
    else:
        openSSL_crypto_lock_list[int(type)].release()
    return

def openSSL_threading_id_callback():
    return long(thread.get_ident())


# Keep a reference of the CFUNC objects to prevent garbage collection
CRYPTOLOCKINGCALLBACK = CFUNCTYPE(None, c_int, c_int, c_char_p,
                                    c_int,use_errno=True, use_last_error=True)
openSSL_threading_locking_callback_cfunc = \
    CRYPTOLOCKINGCALLBACK(openSSL_threading_locking_callback)

CRYPTOIDCALLBACK = CFUNCTYPE(restype=c_ulong,use_errno=True,use_last_error=True)
openSSL_threading_id_callback_cfunc = \
    CRYPTOIDCALLBACK(openSSL_threading_id_callback)


def openSSL_threading_init():
    libcrypto.CRYPTO_set_id_callback.argtypes = [c_void_p]
    libcrypto.CRYPTO_set_id_callback.restype = None

    libcrypto.CRYPTO_set_locking_callback.argtypes = [c_void_p]
    libcrypto.CRYPTO_set_locking_callback.restype = None

    libcrypto.CRYPTO_num_locks.argtypes = []
    libcrypto.CRYPTO_num_locks.restype = c_int
    OPENSSL_CRYPTO_NUM_LOCKS = int(libcrypto.CRYPTO_num_locks())
    for id in xrange(OPENSSL_CRYPTO_NUM_LOCKS):
        new_lock = thread.allocate_lock()
        openSSL_crypto_lock_list.append(new_lock)

    # Register the callbacks needed by OpenSSL for multithreading support
    libcrypto.CRYPTO_set_id_callback(openSSL_threading_id_callback_cfunc)
    libcrypto.CRYPTO_set_locking_callback(openSSL_threading_locking_callback_cfunc)

