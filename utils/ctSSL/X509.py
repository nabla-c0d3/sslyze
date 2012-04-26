#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         X509.py
# Purpose:      Wrapper around the OpenSSL C functions X509_xxx().
#               Messy... because OpenSSL makes an extensive use of C macros
#               to define X509 related functions :(
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------

from ctypes import c_void_p, c_int, c_char_p
from ctypes import create_string_buffer, sizeof, pointer
from load_openssl import libcrypto
import BIO
from errors import ctSSLEmptyValue

class X509:
    def __init__(self, x509_struct):
        self._x509_struct = x509_struct


    def __del__(self):
        """Call OpenSSL X509_free() if a X509 C struct was allocated."""
        if self._x509_struct:
            libcrypto.X509_free(self._x509_struct)
            self._x509_struct = None


    def as_text(self):
        # Print the full certificate to a BIO
        mem_bio = BIO.BIOFactory.new_mem()
        libcrypto.X509_print(mem_bio.get_bio_struct_p(), self._x509_struct)

        # Extract the text from the BIO
        x509_str = mem_bio.read(4096)
        return x509_str


    def get_serial_number(self):
        serial_number_p = libcrypto.X509_get_serialNumber(self._x509_struct)
        mem_bio_p = libcrypto.BIO_new(libcrypto.BIO_s_mem())
        # Print the serial number to a BIO
        libcrypto.i2a_ASN1_INTEGER(mem_bio_p, serial_number_p)

        # Extract the SN from the BIO
        serial_number = create_string_buffer(4096) #TODO: no hardcoded len
        libcrypto.BIO_read(mem_bio_p, serial_number, sizeof(serial_number))
        libcrypto.BIO_free(mem_bio_p)
        return serial_number.value


    def get_issuer(self):
        x509_issuer_p = libcrypto.X509_get_issuer_name(self._x509_struct)
        issuer = create_string_buffer(4096)
        libcrypto.X509_NAME_oneline(x509_issuer_p, issuer, sizeof(issuer))
        return issuer.value


    def get_subject(self):
        x509_subject_p = libcrypto.X509_get_subject_name(self._x509_struct)
        subject = create_string_buffer(4096)
        libcrypto.X509_NAME_oneline(x509_subject_p, subject, sizeof(subject))
        return subject.value


    def get_ext_count(self):
        return libcrypto.X509_get_ext_count(self._x509_struct)


    def get_fingerprint(self, digest='sha1'):
        """
        Based on OpenSSL X509_digest(). Returns a hash of the certificate.
        The digest parameter should be 'md5' or 'sha1'.
        """
        evp_digest = \
            libcrypto.EVP_get_digestbyname(create_string_buffer(digest))
        data_len = c_int(1024) #TODO no hardcoded len
        fingerprint_p = create_string_buffer(data_len.value)
        libcrypto.X509_digest(self._x509_struct, evp_digest, fingerprint_p,
                              pointer(data_len) )

        fingerprint_string = [] # Convert hex stream to a string
        for i in xrange(data_len.value):
            fingerprint_string.append('%02X' % ord( fingerprint_p.raw[i] ) )

        return ''.join(fingerprint_string)


    def get_pubkey_size(self):
        evp_key_struct = libcrypto.X509_get_pubkey(self._x509_struct)
        key_size = libcrypto.EVP_PKEY_size(evp_key_struct)
        return key_size


# The following functions are defined as macros in OpenSSL.
# Obviously prepocessor declarations are not directly available in ctypes.
# As a (temporary?) h4ck I had to use the text version of the certificate
# that I get with as_text() and parse it to extract the values myself :(.


    def _extract_cert_value(self, key):
        """
        Gets the certificate as a text and parses it to extract the value
        corresponding to the given key. H4ck to avoid having to call the
        proper C function because it's defined as a macro.
        """
        value = None
        certificate_lines = self.as_text().splitlines()
        for line in certificate_lines:
            if key in line:
                # Extract the value
                value = line.strip().replace(key , '')
                break

        return value


    def get_version(self):
        return self._extract_cert_value('Version: ')


    def get_not_before(self):
        return self._extract_cert_value('Not Before: ')


    def get_not_after(self):
        return self._extract_cert_value('Not After : ')


    def get_sig_algorithm(self):
        return self._extract_cert_value('Signature Algorithm: ')


# == CTYPE ERRCHECK CALLBACK(S) ==
def errcheck_X509_default(result, func, arguments):
    """
    Default ctype error handler for OpenSSL X509_xxx() C functions called in
    this module.
    """
    if result is None: # Not expecting a NULL pointer back
        raise ctSSLEmptyValue('Error calling ' + str(func.__name__) )
    return result


# == CTYPE INIT ==
def init_X509_functions():
    """
    Tells ctype the argument, return type, and error checking callback of every
    OpenSSL X509_xxx() C functions called in this module.
    """
    libcrypto.i2a_ASN1_INTEGER.argtypes = [c_void_p, c_void_p]
    libcrypto.i2a_ASN1_INTEGER.restype = c_int

    libcrypto.X509_print.argtypes = [c_void_p, c_void_p]
    libcrypto.X509_print.restype = c_int

    libcrypto.X509_get_serialNumber.argtypes = [c_void_p]
    libcrypto.X509_get_serialNumber.restype = c_void_p
    libcrypto.X509_get_serialNumber.errcheck = errcheck_X509_default

    libcrypto.X509_get_issuer_name.argtypes = [c_void_p]
    libcrypto.X509_get_issuer_name.restype = c_void_p
    libcrypto.X509_get_issuer_name.errcheck = errcheck_X509_default

    libcrypto.X509_NAME_oneline.argtypes = [c_void_p, c_void_p, c_int]
    libcrypto.X509_NAME_oneline.restype = c_void_p
    libcrypto.X509_NAME_oneline.errcheck = errcheck_X509_default

    libcrypto.X509_get_subject_name.argtypes = [c_void_p]
    libcrypto.X509_get_subject_name.restype = c_void_p
    libcrypto.X509_get_subject_name.errcheck = errcheck_X509_default

    libcrypto.X509_get_ext_count.argtypes = [c_void_p]
    libcrypto.X509_get_ext_count.restype = c_int

    libcrypto.X509_digest.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
    libcrypto.X509_digest.restype = c_void_p

    # Used with X509_digest()
    libcrypto.EVP_get_digestbyname.argtypes = [c_char_p]
    libcrypto.EVP_get_digestbyname.restype = c_void_p
    libcrypto.EVP_get_digestbyname.errcheck = errcheck_X509_default

    libcrypto.X509_get_pubkey.argtypes = [c_void_p]
    libcrypto.X509_get_pubkey.restype = c_void_p
    libcrypto.X509_get_pubkey.errcheck = errcheck_X509_default

    # Used with X509_get_pubkey()
    libcrypto.EVP_PKEY_size.argtypes = [c_void_p]
    libcrypto.EVP_PKEY_size.restype = c_int

    libcrypto.X509_free.argtypes = [c_void_p]
    libcrypto.X509_free.restype = None
