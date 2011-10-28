#-------------------------------------------------------------------------------
# Name:         errors.py
# Purpose:      Exceptions that can be raised by ctSSL.
#               TODO: Clean/Clarify.
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------
#!/usr/bin/env python

from load_openssl import libssl, libcrypto
from ctypes import c_char_p, c_void_p, c_int, c_long, c_ulong
from ctypes import create_string_buffer

import os



class ctSSLError(Exception):
    """Base class for all ctSSL exceptions."""
    pass

class ctSSLUnexpectedEOF(ctSSLError):
    """Receveid an unexpected EOF."""

class ctSSLEmptyValue(ctSSLError):
    """Receveid a null pointer or an empty buffer from a C function."""
    pass


class OpenSSLError(ctSSLError):
    """
    Base exception for any error returned by a C function from the OpenSSL
    library."""
    pass


class BIOError(OpenSSLError):
    """
    Generic exception for any error returned by the BIO_xxx() C functions
    from the OpenSSL library."""
    pass

class BIOShouldRetry(BIOError):
    pass

class BIOShouldRead(BIOError):
    pass

class BIOShouldWrite(BIOError):
    pass


class SSLError(OpenSSLError):
    """
    Generic exception for any error returned by the SSL_get_error() C
    function from the OpenSSL library."""
    pass

class SSLErrorWantRead(SSLError):
    pass

class SSLErrorWantWrite(SSLError):
    pass

class SSLErrorWantX509Lookup(SSLError):
    pass

class SSLErrorSyscall(SSLError):
    pass

class SSLErrorZeroReturn(SSLError):
    pass

class SSLErrorWantConnect(SSLError):
    pass

class SSLErrorWantAccept(SSLError):
    pass

class SSLErrorSSL(SSLError):
    pass


# Size of the buffer when looking at the OpenSSL error queue
ERROR_STRING_BUFFER_SIZE = 120

# SSL_xxx() errors codes
SSL_ERROR_NONE = 0
SSL_ERROR_SSL = 1
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_WANT_X509_LOOKUP = 4
SSL_ERROR_SYSCALL = 5
SSL_ERROR_ZERO_RETURN = 6
SSL_ERROR_WANT_CONNECT = 7
SSL_ERROR_WANT_ACCEPT = 8



# ==OPENSSL GENERIC ERROR PROCESSING==
def get_openssl_error():
    """
    Read the OpenSSL error queue and return an exception.
    """
    error_code = libcrypto.ERR_get_error()
    error_string = create_string_buffer(ERROR_STRING_BUFFER_SIZE)
    libcrypto.ERR_error_string_n(error_code, error_string,
                                 ERROR_STRING_BUFFER_SIZE)
    return OpenSSLError(error_string.value)



# ==OPENSSL SSL_XXX() ERROR PROCESSING==
def get_openssl_ssl_error(ssl_struct, ret):
    """
    Read the OpenSSL SSL error queue and return an exception.
    """
    ssl_error = libssl.SSL_get_error(ssl_struct, ret)
    if ssl_error == SSL_ERROR_SSL:
        openssl_error = libcrypto.ERR_get_error()
        #if err == 0:
         #   return
        openssl_error_string = create_string_buffer(ERROR_STRING_BUFFER_SIZE)
        libcrypto.ERR_error_string_n(openssl_error, openssl_error_string,
                                        ERROR_STRING_BUFFER_SIZE)
        e = SSLErrorSSL(openssl_error_string.value)

    elif ssl_error == SSL_ERROR_WANT_READ:
        e = SSLErrorWantRead()

    elif ssl_error == SSL_ERROR_WANT_WRITE:
        e = SSLErrorWantWrite()

    elif ssl_error == SSL_ERROR_WANT_X509_LOOKUP:
        e = SSLErrorWantX509Lookup()

    elif ssl_error == SSL_ERROR_SYSCALL:
        openssl_error = libcrypto.ERR_get_error()
        if openssl_error == 0:
            if ret == 0:
                e = SSLErrorSyscall('Connection reset by peer.')
            elif ret == -1: # Error at the BIO level: need to look at errno
                errno_string = str(cp_format_errno(cp_get_errno()))
                #TODO: Linux
                e = SSLErrorSyscall('BIO error: ' + errno_string)
            else:
                e = SSLErrorSyscall()

        else:
            errno_string = str(cp_format_errno(cp_get_errno()))
            e = SSLErrorSyscall(errno_string)

    elif ssl_error == SSL_ERROR_ZERO_RETURN:
        e = SSLErrorZeroReturn()

    elif ssl_error == SSL_ERROR_WANT_CONNECT:
        e = SSLErrorWantConnect()

    elif ssl_error == SSL_ERROR_WANT_ACCEPT:
        e = SSLErrorWantAccept()

    return e


# Cross platform Errno
if os.name == 'nt':
    from ctypes import get_last_error, FormatError
elif os.name == 'posix':
    from ctypes import get_errno
else:
    raise NotImplementedError('OS not supported!')


def cp_get_errno():
    if os.name == 'nt':
        return get_last_error()
    elif os.name == 'posix':
        return get_errno()
    #elif os.name == 'mac': TODO
    else:
        raise NotImplementedError('OS not supported!')


def cp_format_errno(err_code):
    if os.name == 'nt':
        return FormatError(err_code)
    elif os.name == 'posix':
        return os.strerror(err_code)
    #elif os.name == 'mac': TODO
    else:
        raise NotImplementedError('OS not supported!')


def init_ERR_functions():
    """
    Tells ctype the argument, return type, and error checking callback of every
    OpenSSL error functions called in this module.
    """
    libcrypto.ERR_get_error.argtypes = []
    libcrypto.ERR_get_error.restype = c_long

    libcrypto.ERR_error_string_n.argtypes = [c_ulong, c_char_p, c_int]
    libcrypto.ERR_error_string_n.restype = c_int

    libssl.SSL_get_error.argtypes = [c_void_p, c_int]
    libssl.SSL_get_error.restype = c_int



# Ctypes common errcheck callbacks

def errcheck_get_error_if_null(result, func, arguments):
    if result is None:
        raise get_openssl_error()
    return result

def errcheck_get_error_if_eq0(result, func, arguments):
    if result == 0:
        raise errors.get_openssl_error()
    return result