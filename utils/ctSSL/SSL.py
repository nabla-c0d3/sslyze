#-------------------------------------------------------------------------------
# Name:         SSL.py
# Purpose:      Wrapper around the OpenSSL C functions SSL_xxx().
#
# Author:       alban
#
# Copyright:    2011 Alban Diquet
# License:      ctSSL is licensed under the terms of the MIT License.
#-------------------------------------------------------------------------------
#!/usr/bin/env python

from ctypes import create_string_buffer, sizeof, memmove, byref
from ctypes import c_char_p, c_void_p, c_int, c_long
from load_openssl import libssl, OpenSSL_version
import SSL_SESSION, X509, BIO, errors
from errors import errcheck_get_error_if_null, errcheck_get_error_if_eq0

SSL_CTRL_GET_RI_SUPPORT = 76 # SSL_get_secure_renegotiation_support()


class SSL:
    """
    Wrapper around the OpenSSL C functions SSL_xxx().

    It uses a Python socket to handle the network transmission of the data,
    and an OpenSSL BIO pair to encrypt any data about to be sent, and decrypt
    any incoming data.

    @type _socket: socket.socket
    @ivar _socket: Python socket used to handle the network transmission of
    the data.

    @type _ssl_ctx: ctSSL.SSL_CTX.SSL_CTX
    @ivar _ssl_ctx: SSL_CTX associated to the SSL object.

    @type _ssl_struct_p: ctypes.c_void_p
    @ivar _ssl_struct_p: Pointer to the SSL C struct that corresponds to
    that SSL object.

    @type _internal_bio: ctSSL.BIO.BIO
    @ivar _internal_bio: Underlying BIO associated to the SSL C struct.
    Forms a BIO pair with _network_bio.

    @type _network_bio: ctSSL.BIO.BIO
    @ivar _network_bio: BIO used to read to and from the SSL C struct.
    Forms a BIO pair with _internal_bio.
    """

    def __init__(self, ssl_ctx, socket):
        """
        Create a new SSL instance.

        @type ssl_ctx: ctSSL.SSL_CTX.SSL_CTX
        @param ssl_ctx: The SSL_CTX object to be used with that SSL
        connection.

        @type socket: socket.socket
        @param socket: Python socket data will be transmitted on.
        """
        self._socket = socket # The python socket handles network transmission
        self._ssl_ctx = ssl_ctx
        self._ssl_struct_p = libssl.SSL_new(ssl_ctx.get_ssl_ctx_struct_p())
        self._internal_bio = None
        self._network_bio = None

        # Create a BIO pair to handle SSL operations
        (internal_bio, network_bio) = BIO.BIOFactory.new_bio_pair()

        # This BIO will not be implicitely freed by OpenSSL
        network_bio.require_manual_free()
        libssl.SSL_set_bio(self._ssl_struct_p, internal_bio.get_bio_struct_p(),
                           internal_bio.get_bio_struct_p())
        self._internal_bio = internal_bio
        self._network_bio = network_bio


    def __del__(self):
        """Call OpenSSL SSL_free() if a SSL C struct was allocated."""
        if self._ssl_struct_p:
            libssl.SSL_free(self._ssl_struct_p)
            self._ssl_struct_p = None


    def _do_handshake(self):
        """
        Internal handshake loop using SSL_do_handshake().

        Used for initial handshakes in do_client_handshake(), and for
        renegotiations in renegotiate().
        Untested for server-side handshakes so far...

        @raise ctSSL.errors.ctSSLUnexpectedEOF: If an unexpected EOF is received
        while performing the handshake, meaning the connection was closed
        by the peer.
        @raise ctSSL.errors.SSLError: OpenSSL returned an error at the
        SSL level.
        @raise socket.timeout:
        @raise socket.error:
        """
        while True:
            try:
                if libssl.SSL_do_handshake(self._ssl_struct_p) == 1:
                    break # Handshake was successful

            except errors.SSLErrorWantRead as e:
            # OpenSSL is expecting more data from the peer

                # Send available handshake data to the peer
                client_handshake = ''
                size_to_read = self._network_bio.ctrl_pending()
                while size_to_read:
                    client_handshake += self._network_bio.read(size_to_read)
                    size_to_read = self._network_bio.ctrl_pending()
                self._socket.send(client_handshake)

                # Recover the server's response and pass it to the SSL BIO
                server_handshake = self._socket.recv(4096)
                if server_handshake == '': # EOF, handshake failed
                    raise errors.ctSSLUnexpectedEOF(
                        'Handshake failed: Unexpected EOF')
                self._network_bio.write(server_handshake)

            else:
                pass


    def do_client_handshake(self):
        """
        Peform a SSL handshake as the client.

        The socket associated to that SSL connection is expected to already
        be connected to the server (using socket.connect()), when
        do_client_handshake() gets called.

        @raise ctSSL.errors.ctSSLUnexpectedEOF: If an unexpected EOF is received
        while performing the handshake, meaning the connection was closed by the
        peer.
        @raise ctSSL.errors.SSLError: OpenSSL returned an error at the SSL
        level.
        @raise socket.timeout:
        @raise socket.error:
        """
        # Perform the handshake as the client
        libssl.SSL_set_connect_state(self._ssl_struct_p)
        return self._do_handshake()


    #def do_server_handshake(self): TBD


    def renegotiate(self):
        """
        Initiate a SSL renegotiation.

        @raise ctSSL.errors.ctSSLUnexpectedEOF: If an unexpected EOF is received
        while performing the handshake, meaning the connection was closed
        by the peer.
        @raise ctSSL.errors.SSLError: OpenSSL returned an error at the SSL
        level.
        @raise socket.timeout:
        @raise socket.error:

        """
        libssl.SSL_renegotiate(self._ssl_struct_p) # Set the reneg flags to 1
        return self._do_handshake() # Perform the new handshake


    def read(self, size):
        """
        Read some data from the SSL connection.

        @type size: int
        @param size: The maximum number of bytes to return.

        @rtype: str
        @return: A raw buffer of no more than 'size' bytes.

        @raise socket.timeout:
        @raise socket.error:
        """
        if size == 0:
            return ''

        want_read = True
        decrypted_data = ''
        encrypted_data = '1'

        while want_read and len(encrypted_data):
            # Receive the available encrypted data from the other end
            encrypted_data = self._socket.recv(size)
            # Pass that data to the SSL BIO
            self._network_bio.write(encrypted_data)

            while True: # Use SSL_read() to recover the decrypted data
                try: # Read bytes from the SSL BIO
                    read_buffer = create_string_buffer(size)
                    size_read = libssl.SSL_read(self._ssl_struct_p, read_buffer,
                                                size)
                    # Keep the number of bytes that were actually read
                    final_buffer = create_string_buffer(size_read)
                    memmove(final_buffer, read_buffer, size_read)
                    decrypted_data += final_buffer.raw

                except errors.SSLErrorWantRead as e:
                    # If we get SSLErrorWantRead, it means that OpenSSL needs
                    # more data from the peer to finish the read operation
                    break # Restart the read loop

                except errors.SSLErrorZeroReturn as e:
                    # OpenSSL was able to decrypt the message, all done
                    want_read = False
                    break

                else:
                    # OpenSSL was able to decrypt the message, all done
                    want_read = False
                    break

        return decrypted_data


    def write(self, data):
        """
        Write some data to the SSL connection.

        @type data: str
        @param data: The data to transmit to the other party.

        @raise socket.error:
        """
        if len(data) == 0:
            return

        # Pass the cleartext data to the SSL BIO
        write_buffer = create_string_buffer(data)
        libssl.SSL_write(self._ssl_struct_p, write_buffer,
                         sizeof(write_buffer) - 1)

        # And recover it as an encrypted SSL stream of bytes
        encrypted_data = ''
        size_to_read = self._network_bio.ctrl_pending()
        while size_to_read:
            encrypted_data += self._network_bio.read(size_to_read)
            size_to_read = self._network_bio.ctrl_pending()

        # Send the encrypted data to the other end
        self._socket.send(encrypted_data)


    def get_secure_renegotiation_support(self):
        """
        Check whether the peer supports secure renegotiation.
        Directly calls OpenSSL's SSL_get_secure_renegotiation_support().

        @rtype: bool
        @return: True if the peer supports secure renegotiation.

        @raise ctSSL.errors.ctSSLError: The OpenSSL library that was loaded is
        too old and does not support SSL_get_secure_renegotiation_support().
        Use OpenSSL 0.9.8m or later.
        """
        if OpenSSL_version <= 0x9080CFL: # Only available in 0.9.8m or later
            raise errors.ctSSLError('SSL_get_secure_renegotiation_support() '
                                    'is not supported by the version of the '
                                    'OpenSSL library that was loaded. '
                                    'Upgrade to OpenSSL 0.9.8m or later.')

        if libssl.SSL_ctrl(self._ssl_struct_p, SSL_CTRL_GET_RI_SUPPORT, 0,None):
            return True
        else:
            return False


    def shutdown(self):
        """
        Close the SSL channel.
        Directly calls OpenSSL's SSL_shutdown().
        """
        libssl.SSL_shutdown(self._ssl_struct_p)

        # Recover the close notify as an encrypted SSL stream of bytes
        encrypted_data = ''
        size_to_read = self._network_bio.ctrl_pending()
        while size_to_read:
            encrypted_data += self._network_bio.read(size_to_read)
            size_to_read = self._network_bio.ctrl_pending()

        # Send it to the other end, skip socket errors
        # (connection was already closed?)
        try:
            self._socket.send(encrypted_data)
        except:
            pass


    def get_cipher_list(self):
        """
        Get the list of available SSL cipher suites.
        Directly calls OpenSSL's SSL_get_cipher_list().

        @rtype:  L{str}
        @return: A list of the names of available cipher suites.
        """
        cipher_name = libssl.SSL_get_cipher_list(self._ssl_struct_p, 0)
        cipher_list = []
        i=1
        while cipher_name:
            cipher_list.append(cipher_name)
            cipher_name = libssl.SSL_get_cipher_list(self._ssl_struct_p, i)
            i+=1

        return cipher_list


    def get_session(self):
        """
        Retrieve SSL session data.
        Directly calls OpenSSL's SSL_get1_session().

        @rtype: ctSSL.SSL_SESSION.SSL_SESSION
        @return: The SSL_SESSION object for the current connection.

        @raise ctSSLEmptyValue: OpenSSL returned a NULL pointer, meaning there's
        no session available for the current connection.
        """
        ssl_session_p = libssl.SSL_get1_session(self._ssl_struct_p)
        return SSL_SESSION.SSL_SESSION(ssl_session_p)


    def set_session(self, ssl_session):
        """
        Set a SSL session to be used.
        Directly calls OpenSSL's SSL_set_session().

        @type ssl_session: ctSSL.SSL_SESSION.SSL_SESSION
        @param ssl_session: The SSL_SESSION object to be used.
        """
        libssl.SSL_set_session(self._ssl_struct_p,
                               ssl_session.get_ssl_session_struct_p())


    def get_current_cipher(self):
        """
        Return the name of the cipher currently in use.
        Directly calls OpenSSL's SSL_get_current_cipher().

        @rtype: str
        @return: The name of the cipher currently in use.

        @raise ctSSLEmptyValue: OpenSSL returned a NULL pointer, meaning there's
        no current cipher available for the current connection.
        """
        ssl_cipher = libssl.SSL_get_current_cipher(self._ssl_struct_p)
        return libssl.SSL_CIPHER_get_name(ssl_cipher)


    def get_current_cipher_bits(self):
        """
        Return the number of secret bits used for the current cipher.

        @rtype: int
        @return: The number of secret bits used for the current cipher.

        @raise ctSSLEmptyValue: OpenSSL returned a NULL pointer, meaning there's
        no current cipher available for the current connection.
        """
        ssl_cipher = libssl.SSL_get_current_cipher(self._ssl_struct_p)
        return libssl.SSL_CIPHER_get_bits(ssl_cipher, None)


    def get_peer_certificate(self):
        """
        Return the peer's certificate.
        Directly calls OpenSSL's SSL_get_peer_certificate().

        @rtype: ctSSL.X509.X509
        @return: The peer's certificate.

        @raise ctSSLEmptyValue: OpenSSL returned a NULL pointer, meaning there's
        no peer certificate available for the current connection.
        """
        cert = X509.X509(libssl.SSL_get_peer_certificate(self._ssl_struct_p))
        return cert


# == CTYPE ERRCHECK CALLBACK(S) ==
def _errcheck_SSL_default(result, func, arguments):
    """
    Default ctype error handler for OpenSSL SSL_xxx() C functions called in this
    module.
    """
    if result <= 0:
        # If the return value is less than 0, look at the OpenSSL SSL error queue.
        raise errors.get_openssl_ssl_error(arguments[0], result)
    return result


def _errcheck_SSL_shutdown(result, func, arguments):
    if result < 0: # fatal error
        raise errors.get_openssl_ssl_error(arguments[0], result)
    return result


def _errcheck_SSL_get_peer_certificate(result, func, arguments):
    if result is None:
        raise errors.ctSSLEmptyValue('No peer certificate available.')
    return result


def _errcheck_SSL_get_session(result, func, arguments):
    if result is None:
        raise errors.ctSSLEmptyValue('No session available.')
    return result


def _errcheck_get_current_cipher(result, func, arguments):
    if result is None:
        raise errors.ctSSLEmptyValue('No current current cipher available.')
    return result


# == CTYPE INIT ==
def init_SSL_functions():
    """
    Tell ctype the argument, return type, and error checking callback of every
    OpenSSL SSL_xxx() C functions called in this module.
    """
    libssl.SSL_new.argtypes = [c_void_p]
    libssl.SSL_new.restype = c_void_p
    libssl.SSL_new.errcheck = errcheck_get_error_if_null

    libssl.SSL_set_bio.argtypes = [c_void_p, c_void_p, c_void_p]
    libssl.SSL_set_bio.restype = None

    libssl.SSL_free.argtypes = [c_void_p]
    libssl.SSL_free.restype = None

    libssl.SSL_read.argtypes = [c_void_p, c_char_p, c_int]
    libssl.SSL_read.restype = c_int
    libssl.SSL_read.errcheck = _errcheck_SSL_default

    libssl.SSL_write.argtypes = [c_void_p, c_char_p, c_int]
    libssl.SSL_write.restype = c_int
    libssl.SSL_write.errcheck = _errcheck_SSL_default

    libssl.SSL_ctrl.argtypes = [c_void_p, c_int, c_long, c_void_p]
    libssl.SSL_ctrl.restype = c_long

    libssl.SSL_renegotiate.argtypes = [c_void_p]
    libssl.SSL_renegotiate.restype = c_int
    libssl.SSL_renegotiate.errcheck = _errcheck_SSL_default

    libssl.SSL_do_handshake.argtypes = [c_void_p]
    libssl.SSL_do_handshake.restype = c_int
    libssl.SSL_do_handshake.errcheck = _errcheck_SSL_default

    libssl.SSL_shutdown.argtypes = [c_void_p]
    libssl.SSL_shutdown.restype = c_int
    libssl.SSL_shutdown.errcheck = _errcheck_SSL_shutdown

    libssl.SSL_get_error.argtypes = [c_void_p]
    libssl.SSL_state_string_long.restype = c_char_p

    libssl.SSL_get_cipher_list.argtypes = [c_void_p, c_int]
    libssl.SSL_get_cipher_list.restype = c_char_p

    libssl.SSL_get_current_cipher.argtypes = [c_void_p]
    libssl.SSL_get_current_cipher.restype = c_void_p
    libssl.SSL_get_current_cipher.errcheck = _errcheck_get_current_cipher

    libssl.SSL_CIPHER_get_name.argtypes = [c_void_p]
    libssl.SSL_CIPHER_get_name.restype = c_char_p

    libssl.SSL_CIPHER_get_bits.argtypes = [c_void_p, c_void_p]
    libssl.SSL_CIPHER_get_bits.restype = c_int

    libssl.SSL_get1_session.argtypes = [c_void_p]
    libssl.SSL_get1_session.restype = c_void_p
    libssl.SSL_get1_session.errcheck = _errcheck_SSL_get_session

    libssl.SSL_set_session.argtypes = [c_void_p, c_void_p]
    libssl.SSL_set_session.restype = c_int
    libssl.SSL_set_session.errcheck = errcheck_get_error_if_eq0

    libssl.SSL_get_peer_certificate.argtypes = [c_void_p]
    libssl.SSL_get_peer_certificate.restype = c_void_p
    libssl.SSL_get_peer_certificate.errcheck =_errcheck_SSL_get_peer_certificate

    libssl.SSL_pending.argtypes = [c_void_p]
    libssl.SSL_pending.restype = c_int

    libssl.SSL_set_connect_state.argtypes = [c_void_p]
    libssl.SSL_set_connect_state.restype = None

