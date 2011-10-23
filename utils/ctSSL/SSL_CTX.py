#-------------------------------------------------------------------------------
# Name:         SSL_CTX.py
# Purpose:      Wrapper around the OpenSSL C functions SSL_CTX_xxx().
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------
#!/usr/bin/env python


from ctypes import create_string_buffer, CFUNCTYPE, memmove
from ctypes import c_void_p, c_int, c_char_p, c_long
from load_openssl import libssl
from errors import get_openssl_error, ctSSLError


# INTERNAL SSL_CTX CONSTANTS
SSL_CTRL_OPTIONS = 32               # SSL_CTX_get/set_options()
SSL_CTRL_CLEAR_OPTIONS = 32         # SSL_CTX_clear_options()
SSL_CTRL_SET_SESS_CACHE_MODE = 44   # SSL_CTX_set_session_mode()


class SSL_CTX:
    """
    Wrapper around the OpenSSL C functions SSL_CTX_xxx().

    @type _ssl_ctx_struct_p: ctypes.c_void_p
    @ivar _ssl_ctx_struct_p: Pointer to the SSL_CTX C struct that corresponds to
    that SSL_CTX object.

    @type _pem_passwd_cb: ctypes.CFUNCTYPE
    @ivar _pem_passwd_cb: Callback function used for password protected client
    certificates.
    """
    _ssl_ctx_struct_p = None
    _pem_passwd_cb = None

    def __init__(self, ssl_version='sslv23'):
        """
        Create a new SSL_CTX instance.

        @type ssl_version: str
        @param ssl_version: SSL protocol version to use. Should be 'sslv23',
        'sslv2', 'sslv3' or 'tlsv1'.

        @raise ctSSL.errors.ctSSLError: Could not create the SSL_CTX C struct
        (SSL_CTX_new() failed).
        """
        if ssl_version == 'sslv23':
            ssl_version = libssl.SSLv23_method()
        elif ssl_version == 'sslv2':
            ssl_version = libssl.SSLv2_method()
        elif ssl_version == 'sslv3':
            ssl_version = libssl.SSLv3_method()
        elif ssl_version == 'tlsv1':
            ssl_version = libssl.TLSv1_method()
        else:
            raise ctSSLError('Incorrect SSL version. Could not create SSL_CTX.')

        self._ssl_ctx_struct_p = libssl.SSL_CTX_new(ssl_version)


    def __del__(self):
        """Call OpenSSL SSL_CTX_free() if a SSL_CTX C struct was allocated."""
        if self._ssl_ctx_struct_p:
            libssl.SSL_CTX_free(self._ssl_ctx_struct_p)
            self._ssl_ctx_struct_p = None


    def get_ssl_ctx_struct_p(self):
        """
        Get the pointer to the SSL_CTX C struct corresponding to the
        SSL_CTX object.

        @rtype: ctypes.c_void_p
        @return: Pointer to the SSL_CTX C struct.
        """
        return self._ssl_ctx_struct_p


    def  set_verify(self, mode):
        """
        Set the verification flags.
        Directly calls OpenSSL's SSL_CTX_set_verify(), but no verify_callback
        for now.

        @type mode: int
        @param mode: The verification flags to set. See ctSSL.constants.
        """
        libssl.SSL_CTX_set_verify(self._ssl_ctx_struct_p, mode, None)


    def  set_cipher_list(self, cipher_str):
        """
        Set the list of available ciphers.
        Directly calls OpenSSL's SSL_CTX_set_cipher_list().

        @type cipher_str: str
        @param cipher_str: Defines of a list of ciphers.
        """
        str_buffer = create_string_buffer(cipher_str)
        return libssl.SSL_CTX_set_cipher_list(self._ssl_ctx_struct_p,
                                              str_buffer)


    def  set_options(self, option):
        """Directly calls OpenSSL's SSL_CTX_set_options()."""
        libssl.SSL_CTX_ctrl(self._ssl_ctx_struct_p, SSL_CTRL_OPTIONS, option,
                            None)


    def  get_options(self):
        """Directly calls OpenSSL's SSL_CTX_get_options()."""
        return libssl.SSL_CTX_ctrl(self._ssl_ctx_struct_p, SSL_CTRL_OPTIONS, 0,
                                   None)


    def  clear_options(self):
        """Directly calls OpenSSL's SSL_CTX_clear_options()."""
        libssl.SSL_CTX_ctrl(self._ssl_ctx_struct_p, SSL_CTRL_OPTIONS, 0, None)


    def  set_session_cache_mode(self, mode):
        """Directly calls OpenSSL's SSL_CTX_set_session_cache_mode()."""
        libssl.SSL_CTX_ctrl(self._ssl_ctx_struct_p,
                            SSL_CTRL_SET_SESS_CACHE_MODE, mode, None)


    def load_verify_locations(self, cafile):
        """
        Directly calls OpenSSL's SSL_CTX_load_verify_locations(). The third
        argument CAPath is not supported for now.
        """
        #TODO: Clean error if the file can't be found/opened
        cafile_buffer = create_string_buffer(cafile)
        libssl.SSL_CTX_load_verify_locations(self._ssl_ctx_struct_p,
                                             cafile_buffer, None)


    def use_certificate_file(self, cert, certform):
        """Directly calls OpenSSL's SSL_CTX_use_certificate_file()."""
        #TODO: Clean error if the file can't be found/opened
        #TODO: Check openssl version to see if SSL_FILETYPE_ASN1 is supported

        cert_buffer = create_string_buffer(cert)
        libssl.SSL_CTX_use_certificate_file(self._ssl_ctx_struct_p, cert_buffer,
                                            certform);


    def use_PrivateKey_file(self, key, keyform, keypass=None):
        """
        Sets the the passphrase protecting the private key if one is provided
        and then calls OpenSSL's SSL_CTX_use_PrivateKey_file().
        """
        if keypass: # Set up the C callback if a password is needed
            password_buffer = create_string_buffer(keypass)
            PEMPWFUNC = CFUNCTYPE(c_int, c_char_p, c_int, c_int, c_void_p)

            def py_pem_passwd_cb(buf, size, rwflag, userdata):
                memmove(buf, password_buffer, size)
                return 0

            # Keep a reference to prevent garbage collection
            self._pem_passwd_cb = PEMPWFUNC(py_pem_passwd_cb)
            libssl.SSL_CTX_set_default_passwd_cb(self._ssl_ctx_struct_p,
                                                 self._pem_passwd_cb)

        key_buffer = create_string_buffer(key)
        libssl.SSL_CTX_use_PrivateKey_file(self._ssl_ctx_struct_p, key_buffer,
                                           keyform);


    def check_private_key(self):
        """Directly calls OpenSSL's SSL_CTX_check_private_key()."""
        libssl.SSL_CTX_check_private_key(self._ssl_ctx_struct_p)


# == CTYPE ERRCHECK CALLBACK(S) ==
def _errcheck_get_error_if_none(result, func, arguments):
    if result is None:
        raise get_openssl_error()
    return result


def _errcheck_get_error_if_0(result, func, arguments):
    if result is 0:
        raise get_openssl_error()
    return result


# == CTYPE INIT ==
def init_SSL_CTX_functions():
    """
    Tells ctype the argument, return type, and error checking callback of every
    OpenSSL SSL_CTX_xxx() C functions called in this module.
    """

    libssl.TLSv1_method.argtypes = None
    libssl.TLSv1_method.restype = c_void_p

    libssl.SSLv23_method.argtypes = None
    libssl.SSLv23_method.restype = c_void_p

    libssl.SSLv2_method.argtypes = None
    libssl.SSLv2_method.restype = c_void_p

    libssl.SSLv3_method.argtypes = None
    libssl.SSLv3_method.restype = c_void_p

    libssl.SSL_CTX_new.argtypes = [c_void_p]
    libssl.SSL_CTX_new.restype = c_void_p
    libssl.SSL_CTX_new.errcheck = _errcheck_get_error_if_none

    libssl.SSL_CTX_free.argtypes = [c_void_p]
    libssl.SSL_CTX_free.restype = None

    libssl.SSL_CTX_set_verify.argtypes = [c_void_p, c_int, c_void_p]
    libssl.SSL_CTX_set_verify.restype = c_int

    libssl.SSL_CTX_set_cipher_list.argtypes = [c_void_p, c_char_p]
    libssl.SSL_CTX_set_cipher_list.restype = c_int

    libssl.SSL_CTX_ctrl.argtypes = [c_void_p, c_int, c_long, c_void_p]
    libssl.SSL_CTX_ctrl.restype = c_long

    libssl.SSL_CTX_load_verify_locations.argtypes = \
        [c_void_p, c_char_p, c_char_p]
    libssl.SSL_CTX_load_verify_locations.restype = c_int
    libssl.SSL_CTX_load_verify_locations.errcheck = _errcheck_get_error_if_0

    libssl.SSL_CTX_use_certificate_file.argtypes = [c_void_p, c_char_p, c_int]
    libssl.SSL_CTX_use_certificate_file.restype = c_int
    libssl.SSL_CTX_use_certificate_file.errcheck = _errcheck_get_error_if_0

    libssl.SSL_CTX_set_default_passwd_cb.argtypes = [c_void_p, c_void_p]
    libssl.SSL_CTX_set_default_passwd_cb.restype = None

    libssl.SSL_CTX_use_PrivateKey_file.argtypes = [c_void_p, c_char_p, c_int]
    libssl.SSL_CTX_use_PrivateKey_file.restype = c_int
    libssl.SSL_CTX_use_PrivateKey_file.errcheck = _errcheck_get_error_if_0

    libssl.SSL_CTX_check_private_key.argtypes = [c_void_p]
    libssl.SSL_CTX_check_private_key.restype = c_int
    libssl.SSL_CTX_check_private_key.errcheck = _errcheck_get_error_if_0
