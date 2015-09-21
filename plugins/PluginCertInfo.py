#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginCertInfo.py
# Purpose:      Verifies the target server's certificate validity against
#               Mozilla's trusted root store, and prints relevant fields of the
#               certificate.
#
# Author:       aaron, alban
#
# Copyright:    2012 SSLyze developers
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

from os.path import join, dirname, realpath, abspath
import inspect
from xml.etree.ElementTree import Element
import sys

from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.SSLyzeSSLConnection import create_sslyze_connection
from nassl._nassl import OpenSSLError
from nassl import X509_NAME_MISMATCH, X509_NAME_MATCHES_SAN, X509_NAME_MATCHES_CN
from nassl.SslClient import ClientCertificateRequested


# Getting the path to the trust stores is trickier than it sounds due to subtle differences on OS X, Linux and Windows
def get_script_dir(follow_symlinks=True):
    if getattr(sys, 'frozen', False): # py2exe, PyInstaller, cx_Freeze
        path = abspath(sys.executable)
    else:
        path = inspect.getabsfile(get_script_dir)
    if follow_symlinks:
        path = realpath(path)
    return dirname(path)


TRUST_STORES_PATH = join(get_script_dir(), 'data', 'trust_stores')

# We use the Mozilla store for additional things: OCSP and EV validation
MOZILLA_STORE_PATH = join(TRUST_STORES_PATH, 'mozilla.pem')

AVAILABLE_TRUST_STORES = {
    MOZILLA_STORE_PATH: ('Mozilla NSS', '09/2015'),
    join(TRUST_STORES_PATH, 'microsoft.pem'): ('Microsoft', '09/2015'),
    join(TRUST_STORES_PATH, 'apple.pem'): ('Apple', 'OS X 10.10.5'),
    join(TRUST_STORES_PATH, 'java.pem'): ('Java 6', 'Update 65'),
    join(TRUST_STORES_PATH, 'google.pem'): ('Google', '09/2015')
}

EV_OIDS = ['1.2.276.0.44.1.1.1.4', '1.2.392.200091.100.721.1', '1.2.40.0.17.1.22', '1.2.616.1.113527.2.5.1.1', '1.3.159.1.17.1', '1.3.6.1.4.1.13177.10.1.3.10', '1.3.6.1.4.1.14370.1.6', '1.3.6.1.4.1.14777.6.1.1', '1.3.6.1.4.1.14777.6.1.2', '1.3.6.1.4.1.17326.10.14.2.1.2', '1.3.6.1.4.1.17326.10.14.2.2.2', '1.3.6.1.4.1.17326.10.8.12.1.2', '1.3.6.1.4.1.17326.10.8.12.2.2', '1.3.6.1.4.1.22234.2.5.2.3.1', '1.3.6.1.4.1.23223.1.1.1', '1.3.6.1.4.1.29836.1.10', '1.3.6.1.4.1.34697.2.1', '1.3.6.1.4.1.34697.2.2', '1.3.6.1.4.1.34697.2.3', '1.3.6.1.4.1.34697.2.4', '1.3.6.1.4.1.36305.2', '1.3.6.1.4.1.40869.1.1.22.3', '1.3.6.1.4.1.4146.1.1', '1.3.6.1.4.1.4788.2.202.1', '1.3.6.1.4.1.6334.1.100.1', '1.3.6.1.4.1.6449.1.2.1.5.1', '1.3.6.1.4.1.782.1.2.1.8.1', '1.3.6.1.4.1.7879.13.24.1', '1.3.6.1.4.1.8024.0.2.100.1.2', '2.16.156.112554.3', '2.16.528.1.1003.1.2.7', '2.16.578.1.26.1.3.3', '2.16.756.1.83.21.0', '2.16.756.1.89.1.2.1.1', '2.16.792.3.0.3.1.1.5', '2.16.792.3.0.4.1.1.4', '2.16.840.1.113733.1.7.23.6', '2.16.840.1.113733.1.7.48.1', '2.16.840.1.114028.10.1.2', '2.16.840.1.114171.500.9', '2.16.840.1.114404.1.1.2.4.1', '2.16.840.1.114412.2.1', '2.16.840.1.114413.1.7.23.3', '2.16.840.1.114414.1.7.23.3', '2.16.840.1.114414.1.7.24.3']

class PluginCertInfo(PluginBase.PluginBase):

    interface = PluginBase.PluginInterface(title="PluginCertInfo", description='')
    interface.add_command(
        command="certinfo",
        help="Verifies the validity of the server(s) certificate(s) against "
             "various trust stores, checks for support for OCSP stapling, and "
             "prints relevant fields of "
             "the certificate. CERTINFO should be 'basic' or 'full'.",
        dest="certinfo")
    interface.add_option(
        option="ca_file",
        help="Local Certificate Authority file (in PEM format), to verify the "
             "validity of the server(s) certificate(s) against.",
        dest="ca_file")


    TRUST_FORMAT = '{store_name} CA Store ({store_version}):'.format


    def process_task(self, target, command, arg):

        if arg == 'basic':
            txt_output_generator = self._get_basic_text
        elif arg == 'full':
            txt_output_generator = self._get_full_text
        else:
            raise Exception("PluginCertInfo: Unknown command.")

        (host, _, _, _) = target
        thread_pool = ThreadPool()

        if 'ca_file' in self._shared_settings and self._shared_settings['ca_file']:
            AVAILABLE_TRUST_STORES[self._shared_settings['ca_file']] = ('Custom --ca_file', 'N/A')

        for (store_path, _) in AVAILABLE_TRUST_STORES.iteritems():
            # Try to connect with each trust store
            thread_pool.add_job((self._get_cert, (target, store_path)))

        # Start processing the jobs
        thread_pool.start(len(AVAILABLE_TRUST_STORES))

        # Store the results as they come
        x509_cert_chain = []
        (verify_dict, verify_dict_error, x509_cert, ocsp_response) = ({}, {}, None, None)

        for (job, result) in thread_pool.get_result():
            (_, (_, store_path)) = job
            (x509_cert_chain, verify_str, ocsp_response) = result
            # Store the returned verify string for each trust store
            x509_cert = x509_cert_chain[0]  # First cert is always the leaf cert
            store_info = AVAILABLE_TRUST_STORES[store_path]
            verify_dict[store_info] = verify_str

        if x509_cert is None:
            # This means none of the connections were successful. Get out
            for (job, exception) in thread_pool.get_error():
                raise exception

        # Store thread pool errors
        for (job, exception) in thread_pool.get_error():
            (_, (_, store_path)) = job
            error_msg = str(exception.__class__.__name__) + ' - ' + str(exception)

            store_info = AVAILABLE_TRUST_STORES[store_path]
            verify_dict_error[store_info] = error_msg

        thread_pool.join()


        # Results formatting
        # Text output - certificate info
        text_output = [self.PLUGIN_TITLE_FORMAT('Certificate - Content')]
        text_output.extend(txt_output_generator(x509_cert))

        # Text output - trust validation
        text_output.extend(['', self.PLUGIN_TITLE_FORMAT('Certificate - Trust')])

        # Hostname validation
        if self._shared_settings['sni']:
            text_output.append(self.FIELD_FORMAT("SNI enabled with virtual domain:", self._shared_settings['sni']))
        # TODO: Use SNI name for validation when --sni was used
        host_val_dict = {
            X509_NAME_MATCHES_SAN: 'OK - Subject Alternative Name matches',
            X509_NAME_MATCHES_CN: 'OK - Common Name matches',
            X509_NAME_MISMATCH: 'FAILED - Certificate does NOT match ' + host
        }
        text_output.append(self.FIELD_FORMAT("Hostname Validation:", host_val_dict[x509_cert.matches_hostname(host)]))

        # Path validation that was successful
        for ((store_name, store_version), verify_str) in verify_dict.iteritems():
            verify_txt = 'OK - Certificate is trusted' if (verify_str in 'ok') \
                else 'FAILED - Certificate is NOT Trusted: ' + verify_str

            # EV certs - Only Mozilla supported for now
            if (verify_str in 'ok') and ('Mozilla' in store_info):
                if self._is_ev_certificate(x509_cert):
                    verify_txt += ', Extended Validation'

            text_output.append(self.FIELD_FORMAT(self.TRUST_FORMAT(store_name=store_name,
                                                                   store_version=store_version),
                                                 verify_txt))


        # Path validation that ran into errors
        for ((store_name, store_version), error_msg) in verify_dict_error.iteritems():
            verify_txt = 'ERROR: ' + error_msg
            text_output.append(self.FIELD_FORMAT(self.TRUST_FORMAT(store_name=store_name,
                                                                   store_version=store_version),
                                                 verify_txt))

        # Print the Common Names within the certificate chain
        cns_in_cert_chain = []
        for cert in x509_cert_chain:
            cert_identity = self._extract_subject_cn_or_oun(cert)
            cns_in_cert_chain.append(cert_identity)

        text_output.append(self.FIELD_FORMAT('Certificate Chain Received:', str(cns_in_cert_chain)))


        # Text output - OCSP stapling
        text_output.extend(['', self.PLUGIN_TITLE_FORMAT('Certificate - OCSP Stapling')])
        text_output.extend(self._get_ocsp_text(ocsp_response))


        # XML output
        xml_output = Element(command, argument=arg, title='Certificate Information')

        # XML output - certificate chain:  always return the full certificate for each cert in the chain
        cert_chain_xml = Element('certificateChain')

        # First add the leaf certificate
        cert_chain_xml.append(self._format_cert_to_xml(x509_cert_chain[0], 'leaf', self._shared_settings['sni']))

        # Then add every other cert in the chain
        for cert in x509_cert_chain[1:]:
            cert_chain_xml.append(self._format_cert_to_xml(cert, 'intermediate', self._shared_settings['sni']))

        xml_output.append(cert_chain_xml)


        # XML output - trust
        trust_validation_xml = Element('certificateValidation')

        # Hostname validation
        is_hostname_valid = 'False' if (x509_cert.matches_hostname(host) == X509_NAME_MISMATCH) else 'True'
        host_validation_xml = Element('hostnameValidation', serverHostname=host,
                                      certificateMatchesServerHostname=is_hostname_valid)
        trust_validation_xml.append(host_validation_xml)

        # Path validation - OK
        for ((store_name, store_version), verify_str) in verify_dict.iteritems():
            path_attrib_xml = {
                'usingTrustStore': store_name,
                'trustStoreVersion': store_version,
                'validationResult': verify_str
            }

            # EV certs - Only Mozilla supported for now
            if (verify_str in 'ok') and ('Mozilla' in store_info):
                    path_attrib_xml['isExtendedValidationCertificate'] = str(self._is_ev_certificate(x509_cert))

            trust_validation_xml.append(Element('pathValidation', attrib=path_attrib_xml))

        # Path validation - Errors
        for ((store_name, store_version), error_msg) in verify_dict_error.iteritems():
            path_attrib_xml = {
                'usingTrustStore': store_name,
                'trustStoreVersion': store_version,
                'error': error_msg
            }

            trust_validation_xml.append(Element('pathValidation', attrib=path_attrib_xml))


        xml_output.append(trust_validation_xml)


        # XML output - OCSP Stapling
        if ocsp_response is None:
            ocsp_attr_xml = {'isSupported': 'False'}
        else:
            ocsp_attr_xml = {'isSupported': 'True'}
        ocsp_xml = Element('ocspStapling', attrib=ocsp_attr_xml)

        if ocsp_response:
            try:
                ocsp_resp_trusted = str(ocsp_response.verify(MOZILLA_STORE_PATH))

            except OpenSSLError as e:
                if 'certificate verify error' in str(e):
                    ocsp_resp_trusted = 'False'
                else:
                    raise

            ocsp_resp_attr_xml = {'isTrustedByMozillaCAStore': ocsp_resp_trusted}
            ocsp_resp_xmp = Element('ocspResponse', attrib=ocsp_resp_attr_xml)
            for (key, value) in ocsp_response.as_dict().items():
                ocsp_resp_xmp.append(_keyvalue_pair_to_xml(key, value))

            ocsp_xml.append(ocsp_resp_xmp)
            
        xml_output.append(ocsp_xml)

        return PluginBase.PluginResult(text_output, xml_output)


    # FORMATTING FUNCTIONS
    @staticmethod
    def _format_cert_to_xml(x509_cert, x509_cert_position_in_chain_txt, sni_txt):
        cert_attrib_xml = {
            'sha1Fingerprint': x509_cert.get_SHA1_fingerprint()
        }

        if x509_cert_position_in_chain_txt:
            cert_attrib_xml['position'] = x509_cert_position_in_chain_txt

        if sni_txt:
            cert_attrib_xml['suppliedServerNameIndication'] = sni_txt
        cert_xml = Element('certificate', attrib=cert_attrib_xml)

        cert_as_pem_xml = Element('asPEM')
        cert_as_pem_xml.text = x509_cert.as_pem().strip()
        cert_xml.append(cert_as_pem_xml)


        for (key, value) in x509_cert.as_dict().items():

            # Sanitize OpenSSL's output
            if 'subjectPublicKeyInfo' in key:
                # Remove the bit suffix so the element is just a number for the key size
                if 'publicKeySize' in value.keys():
                    value['publicKeySize'] = value['publicKeySize'].split(' bit')[0]

            # Add the XML element
            cert_xml.append(_keyvalue_pair_to_xml(key, value))
        return cert_xml


    def _get_ocsp_text(self, ocsp_resp):

        if ocsp_resp is None:
            return [self.FIELD_FORMAT('NOT SUPPORTED - Server did not send back an OCSP response.', '')]

        ocsp_resp_dict = ocsp_resp.as_dict()
        try:
            ocsp_trust_txt = 'OK - Response is trusted' if ocsp_resp.verify(MOZILLA_STORE_PATH) \
                else 'FAILED - Response is NOT trusted'
        except OpenSSLError as e:
            if 'certificate verify error' in str(e):
                ocsp_trust_txt = 'FAILED - Response is NOT trusted'
            else:
                raise

        ocsp_resp_txt = [
            self.FIELD_FORMAT('OCSP Response Status:', ocsp_resp_dict['responseStatus']),
            self.FIELD_FORMAT('Validation w/ Mozilla\'s CA Store:', ocsp_trust_txt),
            self.FIELD_FORMAT('Responder Id:', ocsp_resp_dict['responderID'])]

        if 'successful' not in ocsp_resp_dict['responseStatus']:
            return ocsp_resp_txt

        ocsp_resp_txt.extend(
            [
                self.FIELD_FORMAT('Cert Status:', ocsp_resp_dict['responses'][0]['certStatus']),
                self.FIELD_FORMAT('Cert Serial Number:', ocsp_resp_dict['responses'][0]['certID']['serialNumber']),
                self.FIELD_FORMAT('This Update:', ocsp_resp_dict['responses'][0]['thisUpdate']),
                self.FIELD_FORMAT('Next Update:', ocsp_resp_dict['responses'][0]['nextUpdate'])
            ]
        )

        return ocsp_resp_txt


    @staticmethod
    def _is_ev_certificate(cert):
        cert_dict = cert.as_dict()
        try:
            policy = cert_dict['extensions']['X509v3 Certificate Policies']['Policy']
            if policy[0] in EV_OIDS:
                return True
        except:
            return False
        return False


    @staticmethod
    def _get_full_text(cert):
        return [cert.as_text()]


    @staticmethod
    def _extract_subject_cn_or_oun(cert):
        try:  # Extract the CN if there's one
            cert_name = cert.as_dict()['subject']['commonName']
        except KeyError:
            # If no common name, display the organizational unit instead
            try:
                cert_name = cert.as_dict()['subject']['organizationalUnitName']
            except KeyError:
                # Give up
                cert_name = 'No Common Name'

        return cert_name


    def _get_basic_text(self, cert):
        cert_dict = cert.as_dict()

        try:  # Extract the CN if there's one
            common_name = cert_dict['subject']['commonName']
        except KeyError:
            common_name = 'None'

        try:  # Extract the CN from the issuer if there's one
            issuer_name = cert_dict['issuer']['commonName']
        except KeyError:
            issuer_name = str(cert_dict['issuer'])

        text_output = [
            self.FIELD_FORMAT("SHA1 Fingerprint:", cert.get_SHA1_fingerprint()),
            self.FIELD_FORMAT("Common Name:", common_name),
            self.FIELD_FORMAT("Issuer:", issuer_name),
            self.FIELD_FORMAT("Serial Number:", cert_dict['serialNumber']),
            self.FIELD_FORMAT("Not Before:", cert_dict['validity']['notBefore']),
            self.FIELD_FORMAT("Not After:", cert_dict['validity']['notAfter']),
            self.FIELD_FORMAT("Signature Algorithm:", cert_dict['signatureAlgorithm']),
            self.FIELD_FORMAT("Public Key Algorithm:", cert_dict['subjectPublicKeyInfo']['publicKeyAlgorithm']),
            self.FIELD_FORMAT("Key Size:", cert_dict['subjectPublicKeyInfo']['publicKeySize'])]

        try:  # Print the Public key exponent if there's one; EC public keys don't have one for example
            text_output.append(self.FIELD_FORMAT("Exponent:", "{0} (0x{0:x})".format(
                int(cert_dict['subjectPublicKeyInfo']['publicKey']['exponent']))))
        except KeyError:
            pass


        try:  # Print the SAN extension if there's one
            text_output.append(self.FIELD_FORMAT('X509v3 Subject Alternative Name:',
                                                 cert_dict['extensions']['X509v3 Subject Alternative Name']))
        except KeyError:
            pass

        return text_output


    def _get_cert(self, target, store_path):
        """
        Connects to the target server and uses the supplied trust store to
        validate the server's certificate. Returns the server's certificate and
        OCSP response.
        """
        (_, _, _, ssl_version) = target
        ssl_conn = create_sslyze_connection(target, self._shared_settings, ssl_version, sslVerifyLocations=store_path)

        # Enable OCSP stapling
        ssl_conn.set_tlsext_status_ocsp()

        try:  # Perform the SSL handshake
            ssl_conn.connect()

            ocsp_resp = ssl_conn.get_tlsext_status_ocsp_resp()
            x509_cert_chain = ssl_conn.get_peer_cert_chain()
            (_, verify_str) = ssl_conn.get_certificate_chain_verify_result()

        except ClientCertificateRequested:  # The server asked for a client cert
            # We can get the server cert anyway
            ocsp_resp = ssl_conn.get_tlsext_status_ocsp_resp()
            x509_cert_chain = ssl_conn.get_peer_cert_chain()
            (_, verify_str) = ssl_conn.get_certificate_chain_verify_result()

        finally:
            ssl_conn.close()

        return x509_cert_chain, verify_str, ocsp_resp


# XML generation
def _create_xml_node(key, value=''):
    key = key.replace(' ', '').strip()  # Remove spaces
    key = key.replace('/', '').strip()  # Remove slashes (S/MIME Capabilities)
    key = key.replace('<', '_')
    key = key.replace('>', '_')

    # Things that would generate invalid XML
    if key[0].isdigit():  # Tags cannot start with a digit
            key = 'oid-' + key

    xml_node = Element(key)
    xml_node.text = value.decode("utf-8").strip()
    return xml_node


def _keyvalue_pair_to_xml(key, value=''):

    if type(value) is str:  # value is a string
        key_xml = _create_xml_node(key, value)

    elif type(value) is int:
        key_xml = _create_xml_node(key, str(value))

    elif value is None:  # no value
        key_xml = _create_xml_node(key)

    elif type(value) is list:
        key_xml = _create_xml_node(key)
        for val in value:
            key_xml.append(_keyvalue_pair_to_xml('listEntry', val))

    elif type(value) is dict:  # value is a list of subnodes
        key_xml = _create_xml_node(key)
        for subkey in value.keys():
            key_xml.append(_keyvalue_pair_to_xml(subkey, value[subkey]))
    else:
        raise Exception()

    return key_xml

