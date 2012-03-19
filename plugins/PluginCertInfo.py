#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginCertInfo.py
# Purpose:      Verifies the target server's certificate validity against
#               Mozilla's trusted root store, and prints relevant fields of the
#               certificate.
#
# Author:       aaron, alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import os
import sys

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, constants, errors


TRUSTED_CA_STORE = os.path.join(sys.path[0], 'mozilla_cacert.pem')


# aaron:
# X.509 certificates contain several required and optional attributes that
# enable the identification of the subject. You can obtain the following list of
# attributes in an X.509 certificate:

    #Version number: The certificate version.
        #Note Different versions (version 1, 2, and 3) of X.509 certificates
        # have evolved over time, to provide additional security and attributes
        # that are bound to the certificate. In practice, only version 3
        # certificates should now be used.

    # Serial number: A unique identifier for the certificate.

    # Signature algorithm ID: The algorithm used to create the digital signature.

    # Issuer name: The name of the certificate issuer.

    # Validity period: The period during which the certificate is valid.

    # Subject name: The name of the subject represented by the certificate. (The
    # subject of a certificate is typically a person, an organization, or a
    # Web/application server.)

    # Subject public key information: The public key algorithm.

    # Issuer unique identifier: The identifier for the issuer.

    # Subject unique identifier: The identifier for the subject.

    # Extensions: Extensions that can be used to store additional information.
    # such as KeyUsage or AlternativeNames.

    # Signed hash of the certificate data: The hash of the preceding fields
    # encrypted using the issuer's private key, which results in a digital
    # signature.


class PluginCertInfo(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginCertInfo",
        description=(
            "Verifies the target server's certificate validity against "
            "Mozilla's trusted root store, and prints relevant fields of "
            "the certificate."))
    available_commands.add_option(
        command="certinfo",
        help="Should be one of: 'basic', 'full', 'serial', 'cn', 'keysize'.",
        dest="certinfo")


    def process_task(self, target, command, args):

        self.target = target
        self.cert = None
        ctSSL_initialize()
        cert_trust = ''
        error_str = ''

        try:
            # First verify the server's certificate
            self.cert = self._get_cert(verify_cert=True)
            cert_trust = 'Certificate is Trusted'

        except errors.SSLErrorSSL as e:
            # Recover the server's certificate without verifying it
            if 'certificate verify failed' in str(e.args):
                cert_trust = 'Certificate is NOT Trusted'
                try:
                    self.cert = self._get_cert(verify_cert=False)
                except Exception as e:
                    error_str = str(e)
            else:
                error_str = str(e)
                
        except Exception:
            ctSSL_cleanup()
            raise
                
        # Result processing
        returnstr = ['  * Certificate : ']
        self.result_format = '      {0:<35}{1:<35}'

        if error_str:
            returnstr.append(self.result_format.format("Error =>", error_str))

        else:
            returnstr.append(self.result_format.format(
                "Validation w/ Mozilla's CA Store:", cert_trust))

            if self.cert:
                if "cn" in args:
                    returnstr.append(self._get_cn())
                if "serial" in args:
                    returnstr.append(self._get_serial())
                if "keysize" in args:
                    returnstr.append(self._get_keysize())
                if "basic" in args:
                    returnstr.extend(self._get_basic())
                if "full" in args:
                    returnstr.append(self._get_full())

        ctSSL_cleanup()
        return returnstr


    def _get_serial(self):
        return self.result_format.format(
            'Serial Number:', self.cert.get_serial_number() )


    def _get_cn(self):
        return self.result_format.format(
            'Subject CN:', self.cert.get_subject_CN() )


    def _get_basic(self):
        result_list = []
        result_list.append(self.result_format.format(
            'Subject CN:', self.cert.get_subject_CN() ))
        result_list.append(self.result_format.format(
            'Issuer:', self.cert.get_issuer() ))
        result_list.append(self.result_format.format(
            'Serial Number:', self.cert.get_serial_number() ))
        result_list.append(self.result_format.format(
            'Not before:', self.cert.get_not_before() ))
        result_list.append(self.result_format.format(
            'Not after:', self.cert.get_not_after() ))
        result_list.append(self.result_format.format(
            'Keysize:', str(self.cert.get_pubkey_size()*8) + ' bits' ))
        result_list.append(self.result_format.format(
            'Signature Algorithm:', self.cert.get_sig_algorithm() ))
        #result_list.append(self.result_format.format('CA Certificate:', self.cert.check_ca() )) #TODO
        result_list.append(self.result_format.format(
            'SHA1 Fingerprint:', self.cert.get_fingerprint() ))
        return result_list

    def _get_keysize(self):
        return self.result_format.format(
            'Keysize:', str(self.cert.get_pubkey_size()*8) + ' bits' )

    def _get_full(self):
        full_cert = self.cert.as_text()
        # Removing the first and the last lines
        full_cert = full_cert.rsplit('\n', 1)[0]
        return full_cert.split('\n', 1)[1]

    def _get_cert(self, verify_cert=False):
        
        ssl_connect = \
            self._create_ssl_connection(self.target)

        if verify_cert:
            ssl_connect.ssl_ctx.load_verify_locations(TRUSTED_CA_STORE)
            ssl_connect.ssl.set_verify(constants.SSL_VERIFY_PEER)

        try: # Perform the SSL handshake
            ssl_connect.connect()
            cert = ssl_connect.ssl.get_peer_certificate()
        except Exception:
            raise
        finally:
            ssl_connect.close()

        return cert
