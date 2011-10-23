#-------------------------------------------------------------------------------
# Name:         __init__.py
# Purpose:      Initialize and cleanup functions for ctSSL.
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------
#!/usr/bin/env python

from ctypes import c_ulong, c_int, CFUNCTYPE, c_char_p, c_void_p
from load_openssl import libssl, libcrypto, ctSSLInitError
import SSL, BIO, SSL_CTX, errors, SSL_SESSION


openSSL_threading = False


def ctSSL_initialize(multithreading=False):
    """
    Initialize ctSSL's ctypes bindings, and OpenSSL libraries and error
    strings. Optionally initializes OpenSSL multithreading support.
    Should always be called before any other ctSSL function.
    """
    # Initialize multithreading
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


def ctSSL_cleanup():
    libcrypto.EVP_cleanup()
    libcrypto.ERR_free_strings()

    # Multithreading cleanup
    if openSSL_threading:
        libcrypto.ERR_remove_state()
        libcrypto.CRYPTO_set_id_callback(None)
        libcrypto.CRYPTO_set_locking_callback(None)



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
CRYPTOLOCKINGCALLBACK = CFUNCTYPE(None, c_int, c_int, c_char_p, c_int,use_errno=True, use_last_error=True)
openSSL_threading_locking_callback_cfunc = CRYPTOLOCKINGCALLBACK(openSSL_threading_locking_callback)

CRYPTOIDCALLBACK = CFUNCTYPE(restype=c_ulong, use_errno=True, use_last_error=True)
openSSL_threading_id_callback_cfunc = CRYPTOIDCALLBACK(openSSL_threading_id_callback)


def openSSL_threading_init():
    libcrypto.CRYPTO_set_id_callback.argtypes = [c_void_p]
    libcrypto.CRYPTO_set_id_callback.restype = None

    libcrypto.CRYPTO_set_locking_callback.argtypes = [c_void_p]
    libcrypto.CRYPTO_set_locking_callback.restype = None

    libcrypto.CRYPTO_num_locks.argtypes = []
    libcrypto.CRYPTO_num_locks.restype = c_int
    CRYPTO_NUM_LOCKS = int(libcrypto.CRYPTO_num_locks())
    for id in xrange(CRYPTO_NUM_LOCKS):
        new_lock = thread.allocate_lock()
        openSSL_crypto_lock_list.append(new_lock)

    # Register the callbacks needed by OpenSSL for multithreading support
    libcrypto.CRYPTO_set_id_callback(openSSL_threading_id_callback_cfunc)
    libcrypto.CRYPTO_set_locking_callback(openSSL_threading_locking_callback_cfunc)

