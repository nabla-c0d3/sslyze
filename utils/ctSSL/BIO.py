#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         BIO.py
# Purpose:      Wrapper around the OpenSSL C functions BIO_xxx().
#               Meant to be internal to ctSSL.
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------

from ctypes import create_string_buffer, sizeof, memmove, byref
from ctypes import c_char_p, c_void_p, c_int, c_long
from load_openssl import libcrypto
from errors import get_openssl_error, BIOError, errcheck_get_error_if_null, \
    BIOShouldRead, BIOShouldRetry, BIOShouldWrite

# INTERNAL BIO CONSTANTS
BIO_C_DO_STATE_MACHINE = 101 # BIO_do_connect()


BIO_FLAGS_READ = 0x1
BIO_FLAGS_WRITE = 0x2
BIO_FLAGS_IO_SPECIAL = 0x04
BIO_FLAGS_RETRY = 0x8

class BIOFactory:

    @classmethod
    def new_mem(self):
        """
        Create a new memory BIO.

        @rtype: ctSSL.BIO.BIO
        @return: The new memory BIO.
        """
        bio_struct_p = libcrypto.BIO_new(libcrypto.BIO_s_mem())
        return BIO(bio_struct_p)



    @classmethod
    def new_bio_pair(self):
        """
        Create a new BIO pair.

        @rtype: (ctSSL.BIO.BIO, ctSSL.BIO.BIO)
        @return: A tuple of BIOs that form a BIO pair.
        """
        bio1_p = c_void_p(0)
        bio2_p = c_void_p(0)
        libcrypto.BIO_new_bio_pair(byref(bio1_p), 0, byref(bio2_p), 0);
        return (BIO(bio1_p), BIO(bio2_p))


    @classmethod
    def new_connect(self, name):
        """
        Create a new connect BIO with the given hostname.

        @type name: str
        @param name: Hostname the BIO should connect to.

        @rtype: ctSSL.BIO.BIO
        @return: The new connect BIO.
        """
        bio_struct_p = libcrypto.BIO_new_connect(name)
        return BIO(bio_struct_p)


class BIO:
    """
    Wrapper around the OpenSSL C functions BIO_xxx().

    @type _bio_struct_p: ctypes.c_void_p
    @ivar _bio_struct_p: Pointer to the BIO C struct that corresponds to
    that BIO object.
    @type _implicit_free: boolean
    @ivar _implicit_free: Tells whether the BIO struct has to be manually freed.
    """

    def __init__(self, bio_struct_p):
        """
        Create a new BIO instance.
        Should not be called directly. Use BIOFactory.

        @type bio_struct_p: ctypes.c_void_p
        @param bio_struct_p: Pointer to the OpenSSL BIO C struct.
        """
        self._bio_struct_p = bio_struct_p
        self._implicit_free = True


    def __del__(self):
        """
        Call OpenSSL BIO_free() if a BIO C struct was allocated and wasn't
        implicitely freed by OpenSSL.
        """
        if not self._implicit_free:
            if self._bio_struct_p:
                libcrypto.BIO_free(self._bio_struct_p)
                self._bio_struct_p = None


    def require_manual_free(self):
        """BIO has to be explicitely freed by calling BIO_free()."""
        self._implicit_free = False


    def get_bio_struct_p(self):
        """
        Get the pointer to the BIO C struct corresponding to the BIO object.

        @rtype: ctypes.c_void_p
        @return: Pointer to the BIO C struct.
        """
        return self._bio_struct_p


    def do_connect(self):
        """
        Attempt to connect the BIO.
        Directly calls OpenSSL's BIO_do_connect().
        """
        libcrypto.BIO_ctrl(self._bio_struct_p, BIO_C_DO_STATE_MACHINE, 0, None)


    def read(self, size):
        """
        Read some data from the BIO.

        @type size: int
        @param size: The maximum number of bytes to return.

        @rtype: str
        @return: A raw buffer of no more than 'size' bytes.
        """
        read_buffer = create_string_buffer(size)
        size_read = libcrypto.BIO_read(self._bio_struct_p, read_buffer, size)
        # Returning the number of bytes that were actually read
        final_buffer = create_string_buffer(size_read)
        memmove(final_buffer, read_buffer, size_read)
        return final_buffer.raw


    def write(self, data):
        """
        Write some data to the BIO.

        @type data: str
        @param data: The data to transmit to the other party.
        """
        if len(data) == 0:
            return
        write_buffer = create_string_buffer(data)
        libcrypto.BIO_write(self._bio_struct_p, write_buffer,
                                sizeof(write_buffer) - 1)


    def ctrl_pending(self):
        """Directly calls OpenSSL's BIO_ctrl_pending()."""
        return libcrypto.BIO_ctrl_pending(self._bio_struct_p)



# == CTYPE ERRCHECK CALLBACK(S) ==
def _errcheck_BIO_default(result, func, arguments):
    """
    Default ctype error handler for OpenSSL BIO_xxx() C functions called in this
    module.
    """
    if result <= 0:
        # If the return value is less than 0, look at the OpenSSL error queue.
        raise get_openssl_error()
    return result


def _errcheck_BIO_read(result, func, arguments):
    """
    Ctype error handler for the OpenSSL BIO_read() C function.
    """
    if result <= 0:
        (bio_struct_p, buffer_p, buffer_size) = arguments
        # TODO: Is this really used ?
        if libcrypto.BIO_test_flags(bio_struct_p, BIO_FLAGS_READ):
            raise BIOShouldRead() # TODO: Put a description of the error
        else:
            if libcrypto.BIO_test_flags(bio_struct_p, BIO_FLAGS_RETRY):
                raise BIOShouldRetry()
            else:
                if libcrypto.BIO_test_flags(bio_struct_p, BIO_FLAGS_IO_SPECIAL):
                    raise BIOError()

    return result

def _errcheck_BIO_write(result, func, arguments):
    """
    Ctype error handler for the OpenSSL BIO_write() C function.
    """
    if result <= 0:
        (bio_struct_p, buffer_p, buffer_size) = arguments
        # TODO: Is this really used ?
        if libcrypto.BIO_test_flags(bio_struct_p, BIO_FLAGS_WRITE):
            raise BIOShouldWrite() # TODO: Put a description of the error
        else:
            if libcrypto.BIO_test_flags(bio_struct_p, BIO_FLAGS_RETRY):
                raise BIOShouldRetry()
            else:
                if libcrypto.BIO_test_flags(bio_struct_p, BIO_FLAGS_IO_SPECIAL):
                    raise BIOError()

    return result


# == CTYPE INIT ==
def init_BIO_functions():
    """
    Tells ctype the argument, return type, and error checking callback of every
    OpenSSL BIO_xxx() C functions called in this module.
    """
    libcrypto.BIO_new_connect.argtypes = [c_char_p]
    libcrypto.BIO_new_connect.restype = c_void_p
    libcrypto.BIO_new_connect.errcheck = errcheck_get_error_if_null

    libcrypto.BIO_ctrl.argtypes = [c_void_p, c_int, c_long, c_void_p]
    libcrypto.BIO_ctrl.restype = c_long
    libcrypto.BIO_ctrl.errcheck = _errcheck_BIO_default

    libcrypto.BIO_read.argtypes = [c_void_p, c_char_p, c_int]
    libcrypto.BIO_read.restype = c_int
    libcrypto.BIO_read.errcheck = _errcheck_BIO_read

    libcrypto.BIO_write.argtypes = [c_void_p, c_char_p, c_int]
    libcrypto.BIO_write.restype = c_int
    libcrypto.BIO_write.errcheck = _errcheck_BIO_write

    libcrypto.BIO_free.argtypes = [c_void_p]
    libcrypto.BIO_free.restype = c_int

    libcrypto.BIO_test_flags.argtypes = [c_void_p, c_int]
    libcrypto.BIO_test_flags.restype = c_int

    libcrypto.BIO_new_bio_pair.argtypes = [c_void_p, c_int, c_void_p, c_int]
    libcrypto.BIO_new_bio_pair.restype = c_int

    libcrypto.BIO_ctrl_pending.argtypes = [c_void_p]
    libcrypto.BIO_ctrl_pending.restype = c_int

    libcrypto.BIO_s_mem.argtypes = None
    libcrypto.BIO_s_mem.restype = c_void_p

    libcrypto.BIO_new.argtypes = [c_void_p]
    libcrypto.BIO_new.restype = c_void_p
    libcrypto.BIO_new.errcheck = errcheck_get_error_if_null

