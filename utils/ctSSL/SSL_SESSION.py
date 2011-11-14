#-------------------------------------------------------------------------------
# Name:         SSL_SESSION.py
# Purpose:      Wrapper around the OpenSSL C functions SSL_SESSION_xxx().
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------
#!/usr/bin/env python

from ctypes import c_int, c_void_p
from load_openssl import libssl
import BIO

class SSL_SESSION:
    """
    Wrapper around the OpenSSL C functions SSL_SESSION_xxx().

    @type _ssl_session_struct_p: ctypes.c_void_p
    @ivar _ssl_session_struct_p: Pointer to the SSL_SESSION C struct that
    corresponds to that SSL_SESSION object.
    """

    def __init__(self, _ssl_session_struct_p):
        """
        Create a new SSL_SESSION instance.

        @type _ssl_session_struct_p: ctypes.c_void_p
        @param _ssl_session_struct_p: Pointer to the OpenSSL SSL_SESSION C struct.
        """
        self._ssl_session_struct_p = _ssl_session_struct_p


    def __del__(self):
        """
        Call OpenSSL SSL_SESSION_free() if a SSL_SESSION C struct was
        allocated.
        """
        if self._ssl_session_struct_p:
            libssl.SSL_SESSION_free(self._ssl_session_struct_p)
            self._ssl_session_struct_p = None


    def get_ssl_session_struct_p(self):
        """
        Get the pointer to the SSL_SESSION C struct corresponding to the
        SSL_SESSION object.

        @rtype: ctypes.c_void_p
        @return: Pointer to the SSL_SESSION C struct.
        """
        return self._ssl_session_struct_p


    def as_text(self):
        """
        Return the text description of the SSL session.

        @rtype: str
        @return: The text description of the SSL session.
        """
        # Print the session description to a BIO
        mem_bio = BIO.BIOFactory.new_mem()
        libssl.SSL_SESSION_print(
            mem_bio.get_bio_struct_p(),
            self._ssl_session_struct_p)

        # Extract the description from the BIO
        session_str = mem_bio.read(4096)
        return session_str


# == CTYPE INIT ==
def init_SSL_SESSION_functions():
    """
    Tells ctype the argument, return type, and error checking callback of every
    OpenSSL SSL_SESSION_xxx() C functions called in this module.
    """
    libssl.SSL_SESSION_print.argtypes = [c_void_p, c_void_p]
    libssl.SSL_SESSION_print.restype = c_int

    libssl.SSL_SESSION_free.argtypes = [c_void_p]
    libssl.SSL_SESSION_free.restype = c_int