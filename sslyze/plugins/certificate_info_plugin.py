# -*- coding: utf-8 -*-
"""Plugin to retrieve and validate the server's certificate.
"""

import inspect
import sys
from os.path import join, dirname, realpath, abspath
from xml.etree.ElementTree import Element

from nassl import X509_NAME_MISMATCH, X509_NAME_MATCHES_SAN, X509_NAME_MATCHES_CN
from nassl.ssl_client import ClientCertificateRequested
from nassl._nassl import OpenSSLError

from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginResult
from sslyze.utils.thread_pool import ThreadPool


# Getting the path to the trust stores is trickier than it sounds due to subtle differences on OS X, Linux and Windows
def get_script_dir(follow_symlinks=True):
    if getattr(sys, 'frozen', False):
        # py2exe, PyInstaller, cx_Freeze
        path = abspath(sys.executable)
    else:
        path = inspect.getabsfile(get_script_dir)
    if follow_symlinks:
        path = realpath(path)
    return dirname(path)


TRUST_STORES_PATH = join(get_script_dir(), 'data', 'trust_stores')

# We use the Mozilla store for additional things: OCSP and EV validation
MOZILLA_STORE_PATH = join(TRUST_STORES_PATH, 'mozilla.pem')
MOZILLA_EV_OIDS = ['1.2.276.0.44.1.1.1.4', '1.2.392.200091.100.721.1', '1.2.40.0.17.1.22',
                   '1.2.616.1.113527.2.5.1.1', '1.3.159.1.17.1', '1.3.6.1.4.1.13177.10.1.3.10',
                   '1.3.6.1.4.1.14370.1.6', '1.3.6.1.4.1.14777.6.1.1', '1.3.6.1.4.1.14777.6.1.2',
                   '1.3.6.1.4.1.17326.10.14.2.1.2', '1.3.6.1.4.1.17326.10.14.2.2.2',
                   '1.3.6.1.4.1.17326.10.8.12.1.2', '1.3.6.1.4.1.17326.10.8.12.2.2', '1.3.6.1.4.1.22234.2.5.2.3.1',
                   '1.3.6.1.4.1.23223.1.1.1', '1.3.6.1.4.1.29836.1.10', '1.3.6.1.4.1.34697.2.1',
                   '1.3.6.1.4.1.34697.2.2', '1.3.6.1.4.1.34697.2.3', '1.3.6.1.4.1.34697.2.4',
                   '1.3.6.1.4.1.36305.2', '1.3.6.1.4.1.40869.1.1.22.3', '1.3.6.1.4.1.4146.1.1',
                   '1.3.6.1.4.1.4788.2.202.1', '1.3.6.1.4.1.6334.1.100.1', '1.3.6.1.4.1.6449.1.2.1.5.1',
                   '1.3.6.1.4.1.782.1.2.1.8.1', '1.3.6.1.4.1.7879.13.24.1', '1.3.6.1.4.1.8024.0.2.100.1.2',
                   '2.16.156.112554.3', '2.16.528.1.1003.1.2.7', '2.16.578.1.26.1.3.3', '2.16.756.1.83.21.0',
                   '2.16.756.1.89.1.2.1.1', '2.16.792.3.0.3.1.1.5', '2.16.792.3.0.4.1.1.4',
                   '2.16.840.1.113733.1.7.23.6', '2.16.840.1.113733.1.7.48.1', '2.16.840.1.114028.10.1.2',
                   '2.16.840.1.114171.500.9', '2.16.840.1.114404.1.1.2.4.1', '2.16.840.1.114412.2.1',
                   '2.16.840.1.114413.1.7.23.3', '2.16.840.1.114414.1.7.23.3', '2.16.840.1.114414.1.7.24.3']


class TrustStore(object):
    def __init__(self, path, name, version):
        self.path = path
        self.name = name
        self.version = version

DEFAULT_TRUST_STORE_LIST = [
    TrustStore(MOZILLA_STORE_PATH, 'Mozilla NSS', '02/2016'),
    TrustStore(join(TRUST_STORES_PATH, 'microsoft.pem'), 'Microsoft', '02/2016'),
    TrustStore(join(TRUST_STORES_PATH, 'apple.pem'), 'Apple', 'OS X 10.11.3'),
    TrustStore(join(TRUST_STORES_PATH, 'java.pem'), 'Java 6', 'Update 65'),
    TrustStore(join(TRUST_STORES_PATH, 'aosp.pem'), 'AOSP', 'N Preview 2'),
]


class PathValidationResult(object):
    """The result of trying to validate a server's certificate chain using a specific trust store.
    """
    def __init__(self, trust_store, verify_string):
        # The trust store used for validation
        self.trust_store = trust_store

        # The string returned by OpenSSL's validation function
        self.verify_string = verify_string
        self.is_certificate_trusted = True if verify_string == 'ok' else False


class PathValidationError(object):
    """An exception was raised while trying to validate a server's certificate using a specific trust store; should
    never happen.
    """
    def __init__(self, trust_store, exception):
        self.trust_store = trust_store
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = '{} - {}'.format(str(exception.__class__.__name__), str(exception))


class Certificate(object):
    """Pick-able object for storing information contained within an nassl.X509Certificate. This is needed because we
     cannot directly send an X509Certificate to a different process (which would happen during a scan) as it is not
     pickable.
     """

    def __init__(self, x509_certificate):
        self.as_pem = x509_certificate.as_pem().strip()
        self.as_text = x509_certificate.as_text()
        self.as_dict = x509_certificate.as_dict()
        self.sha1_fingerprint = x509_certificate.get_SHA1_fingerprint()


class CertificateInfoPlugin(plugin_base.PluginBase):

    interface = plugin_base.PluginInterface(title="CertificateInfoPlugin", description='')
    interface.add_command(
        command="certinfo_basic",
        help="Verifies the validity of the server(s) certificate(s) against various trust stores, checks for support "
             "for OCSP stapling, and prints relevant fields of the certificate."
    )
    interface.add_command(
        command="certinfo_full",
        help="Same as --certinfo_basic but also prints the full server certificate."
    )
    interface.add_option(
        option="ca_file",
        help="Local Certificate Authority file (in PEM format), to verify the "
             "validity of the server(s) certificate(s) against.",
        dest="ca_file"
    )


    def process_task(self, server_info, command, options_dict=None):

        if command == 'certinfo_basic':
            result_class = CertInfoBasicResult
        elif command == 'certinfo_full':
            result_class = CertInfoFullResult
        else:
            raise ValueError("PluginCertInfo: Unknown command.")

        final_trust_store_list = list(DEFAULT_TRUST_STORE_LIST)
        if options_dict and 'ca_file' in options_dict.keys():
            final_trust_store_list.append(TrustStore(options_dict['ca_file'], 'Custom --ca_file', 'N/A'))

        thread_pool = ThreadPool()
        for trust_store in final_trust_store_list:
            # Try to connect with each trust store
            thread_pool.add_job((self._get_certificate_chain, (server_info, trust_store)))

        # Start processing the jobs; one thread per trust
        thread_pool.start(len(final_trust_store_list))

        # Store the results as they come
        certificate_chain = []
        path_validation_result_list = []
        path_validation_error_list = []
        ocsp_response = None

        for (job, result) in thread_pool.get_result():
            (_, (_, trust_store)) = job
            certificate_chain, validation_result, ocsp_response = result
            # Store the returned verify string for each trust store
            path_validation_result_list.append(PathValidationResult(trust_store, validation_result))

        # Store thread pool errors
        last_exception = None
        for (job, exception) in thread_pool.get_error():
            (_, (_, trust_store)) = job
            path_validation_error_list.append(PathValidationError(trust_store, exception))
            last_exception = exception

        thread_pool.join()

        if len(path_validation_error_list) == len(final_trust_store_list):
            # All connections failed unexpectedly; raise an exception instead of returning a result
            raise RuntimeError('Could not connect to the server; last error: {}'.format(last_exception))

        # All done
        return result_class(server_info, command, options_dict, certificate_chain, path_validation_result_list,
                            path_validation_error_list, ocsp_response)


    def _get_certificate_chain(self, server_info, trust_store):
        """Connects to the target server and uses the supplied trust store to validate the server's certificate.
        Returns the server's certificate and OCSP response.
        """
        ssl_connection = server_info.get_preconfigured_ssl_connection(ssl_verify_locations=trust_store.path)

        # Enable OCSP stapling
        ssl_connection.set_tlsext_status_ocsp()

        try:  # Perform the SSL handshake
            ssl_connection.connect()

            ocsp_response = ssl_connection.get_tlsext_status_ocsp_resp()
            x509_cert_chain = ssl_connection.get_peer_cert_chain()
            (_, verify_str) = ssl_connection.get_certificate_chain_verify_result()

        except ClientCertificateRequested:  # The server asked for a client cert
            # We can get the server cert anyway
            ocsp_response = ssl_connection.get_tlsext_status_ocsp_resp()
            x509_cert_chain = ssl_connection.get_peer_cert_chain()
            (_, verify_str) = ssl_connection.get_certificate_chain_verify_result()

        finally:
            ssl_connection.close()

        return x509_cert_chain, verify_str, ocsp_response


class CertInfoFullResult(PluginResult):
    """The result of running --certinfo_full on a specific server.

    Attributes:
        certificate_chain (List[Certificate]): The server's certificate chain; index 0 is the leaf certificate.
        is_leaf_certificate_ev (bool): True if the leaf certificate is Extended Validation according to Mozilla.
        path_validation_result_list (List[PathValidationResult]): A list of attempts at validating the server's
            certificate chain path using various trust stores.
        path_validation_error_list (List[PathValidationError]):  A list of attempts at validating the server's
            certificate chain path that triggered an unexpected error.
        hostname_validation_result (int): Validation result of the certificate hostname.
        ocsp_response (Optional[dict]): The OCSP response returned by the server.
        is_ocsp_response_trusted (Optional[bool]): True if the OCSP response is trusted using the Mozilla trust store.
    """

    COMMAND_TITLE = 'Certificate Basic Information'

    def __init__(self, server_info, plugin_command, plugin_options, certificate_chain, path_validation_result_list,
                            path_validation_error_list, ocsp_response):
        super(CertInfoFullResult, self).__init__(server_info, plugin_command, plugin_options)

        # We only keep the dictionary as a nassl.OcspResponse is not pickable
        self.ocsp_response = ocsp_response.as_dict() if ocsp_response else None
        self.is_ocsp_response_trusted = ocsp_response.verify(MOZILLA_STORE_PATH) if ocsp_response else False

        # We create pickable Certificates from nassl.X509Certificates which are not pickable
        self.certificate_chain = [Certificate(x509_cert) for x509_cert in certificate_chain]

        self.is_leaf_certificate_ev = False
        try:
            policy = self.certificate_chain[0].as_dict['extensions']['X509v3 Certificate Policies']['Policy']
        except:
            # Certificate which don't have this extension
            pass
        else:
            if policy[0] in MOZILLA_EV_OIDS:
                self.is_leaf_certificate_ev = True

        self.path_validation_result_list = path_validation_result_list
        self.path_validation_error_list = path_validation_error_list
        self.hostname_validation_result = certificate_chain[0].matches_hostname(server_info.tls_server_name_indication)
        self.is_certificate_chain_order_valid = self._is_certificate_chain_order_valid(self.certificate_chain)


    def _get_certificate_text(self):
        """For --certinfo_full, we just print the whole certificate.
        """
        return [self.certificate_chain[0].as_text]


    @staticmethod
    def _extract_subject_cn_or_oun(certificate):
        try:
            # Extract the CN if there's one
            cert_name = certificate.as_dict['subject']['commonName']
        except KeyError:
            # If no common name, display the organizational unit instead
            try:
                cert_name = certificate.as_dict['subject']['organizationalUnitName']
            except KeyError:
                # Give up
                cert_name = 'No Common Name'
        return unicode(cert_name, 'utf-8')


    @staticmethod
    def _is_root_certificate(certificate):
        is_root_certificate = False
        with open(MOZILLA_STORE_PATH, 'r') as store_file:
            store_content = store_file.read()
            # Stripping new lines as the lines will have a different length in the trust store VS in the certificate
            if certificate.as_pem.replace('\n', '') in store_content.replace('\n', ''):
                is_root_certificate = True
        return is_root_certificate


    @staticmethod
    def _is_certificate_chain_order_valid(certificate_chain):
        for index, cert in enumerate(certificate_chain):
            current_subject = cert.as_dict['subject']

            if index > 0:
                # Compare the current subject with the previous issuer in the chain
                if current_subject != previous_issuer:
                    return False
            try:
                previous_issuer = cert.as_dict['issuer']
            except KeyError:
                # Missing issuer; this is okay if this is the last cert
                previous_issuer = "missing issuer {}".format(index)
        return True


    HOSTNAME_VALIDATION_TEXT = {
        X509_NAME_MATCHES_SAN: 'OK - Subject Alternative Name matches {hostname}'.format,
        X509_NAME_MATCHES_CN: 'OK - Common Name matches {hostname}'.format,
        X509_NAME_MISMATCH: 'FAILED - Certificate does NOT match {hostname}'.format
    }

    TRUST_FORMAT = '{store_name} CA Store ({store_version}):'.format


    def as_text(self):
        text_output = [self.PLUGIN_TITLE_FORMAT(self.COMMAND_TITLE)]
        text_output.extend(self._get_certificate_text())

        # Trust section
        text_output.extend(['', self.PLUGIN_TITLE_FORMAT('Certificate - Trust')])

        # Hostname validation
        server_name_indication = self.server_info.tls_server_name_indication
        if self.server_info.tls_server_name_indication != self.server_info.hostname:
            text_output.append(self.FIELD_FORMAT("SNI enabled with virtual domain:", server_name_indication))

        text_output.append(self.FIELD_FORMAT(
                "Hostname Validation:",
                self.HOSTNAME_VALIDATION_TEXT[self.hostname_validation_result](hostname=server_name_indication))
        )

        # Path validation that was successfully tested
        for path_result in self.path_validation_result_list:
            if path_result.is_certificate_trusted:
                # EV certs - Only Mozilla supported for now
                ev_txt = ''
                if self.is_leaf_certificate_ev and 'Mozilla' in path_result.trust_store.name:
                    ev_txt = ', Extended Validation'
                path_txt = 'OK - Certificate is trusted{}'.format(ev_txt)

            else:
                path_txt = 'FAILED - Certificate is NOT Trusted: {}'.format(path_result.verify_string)

            text_output.append(self.FIELD_FORMAT(self.TRUST_FORMAT(store_name=path_result.trust_store.name,
                                                                   store_version=path_result.trust_store.version),
                                                 path_txt))

        # Path validation that ran into errors
        for path_error in self.path_validation_error_list:
            error_txt = 'ERROR: {}'.format(path_error.error_message)
            text_output.append(self.FIELD_FORMAT(self.TRUST_FORMAT(store_name=path_result.trust_store.name,
                                                                   store_version=path_result.trust_store.version),
                                                 error_txt))

        # Print the Common Names within the certificate chain and find if there are SHA1-signed certificates
        cns_in_certificate_chain = []
        has_sha1_signed_certificate = False
        for cert in self.certificate_chain:
            cert_identity = self._extract_subject_cn_or_oun(cert)
            cns_in_certificate_chain.append(cert_identity)

            if not self._is_root_certificate(cert) and "sha1" in cert.as_dict['signatureAlgorithm']:
                has_sha1_signed_certificate = True

        sha1_text = 'OK - No SHA1-signed certificate in the chain' \
            if not has_sha1_signed_certificate \
            else 'INSECURE - SHA1-signed certificate in the chain'
        text_output.append(self.FIELD_FORMAT('Weak Signature:', sha1_text))
        text_output.append(self.FIELD_FORMAT('Certificate Chain Received:', ' --> '.join(cns_in_certificate_chain)))

        chain_order_txt = 'OK - Order is valid' if self.is_certificate_chain_order_valid \
            else 'FAILED - Certificate chain out of order!'
        text_output.append(self.FIELD_FORMAT('Certificate Chain Order:', chain_order_txt))

        # OCSP stapling
        text_output.extend(['', self.PLUGIN_TITLE_FORMAT('Certificate - OCSP Stapling')])

        if self.ocsp_response is None:
            text_output.append(self.FIELD_FORMAT('', 'NOT SUPPORTED - Server did not send back an OCSP response.'))

        else:
            try:
                ocsp_trust_txt = 'OK - Response is trusted' \
                    if self.is_ocsp_response_trusted \
                    else 'FAILED - Response is NOT trusted'
            except OpenSSLError as e:
                if 'certificate verify error' in str(e):
                    ocsp_trust_txt = 'FAILED - Response is NOT trusted'
                else:
                    raise

            ocsp_resp_txt = [
                self.FIELD_FORMAT('OCSP Response Status:', self.ocsp_response['responseStatus']),
                self.FIELD_FORMAT('Validation w/ Mozilla\'s CA Store:', ocsp_trust_txt),
                self.FIELD_FORMAT('Responder Id:', self.ocsp_response['responderID'])]

            if 'successful' in self.ocsp_response['responseStatus']:
                ocsp_resp_txt.extend([
                    self.FIELD_FORMAT('Cert Status:', self.ocsp_response['responses'][0]['certStatus']),
                    self.FIELD_FORMAT('Cert Serial Number:', self.ocsp_response['responses'][0]['certID']['serialNumber']),
                    self.FIELD_FORMAT('This Update:', self.ocsp_response['responses'][0]['thisUpdate']),
                    self.FIELD_FORMAT('Next Update:', self.ocsp_response['responses'][0]['nextUpdate'])
                ])
            text_output.extend(ocsp_resp_txt)

        # All done
        return text_output


    def as_xml(self):
        xml_output = Element(self.plugin_command, title=self.COMMAND_TITLE)

        # Certificate chain
        cert_xml_list = []
        has_sha1_signed_certificate = False
        for index, certificate in enumerate(self.certificate_chain, start=0):

            if not self._is_root_certificate(certificate) and "sha1" in certificate.as_dict['signatureAlgorithm']:
                has_sha1_signed_certificate = True

            cert_xml = Element('certificate', attrib={
                'sha1Fingerprint': certificate.sha1_fingerprint,
                'position': 'leaf' if index == 0 else 'intermediate',
                'suppliedServerNameIndication': self.server_info.tls_server_name_indication
            })

            # Add the PEM cert
            cert_as_pem_xml = Element('asPEM')
            cert_as_pem_xml.text = certificate.as_pem
            cert_xml.append(cert_as_pem_xml)

            # Add the parsed certificate
            for key, value in certificate.as_dict.items():
                # Sanitize OpenSSL's output
                if 'subjectPublicKeyInfo' in key:
                    # Remove the bit suffix so the element is just a number for the key size
                    if 'publicKeySize' in value.keys():
                        value['publicKeySize'] = value['publicKeySize'].split(' bit')[0]

                cert_xml.append(_keyvalue_pair_to_xml(key, value))

            cert_xml_list.append(cert_xml)

        cert_chain_xml = Element('certificateChain',
                                 attrib={'hasSha1SignedCertificate': str(has_sha1_signed_certificate),
                                         'isChainOrderValid': str(self.is_certificate_chain_order_valid)})
        for cert_xml in cert_xml_list:
            cert_chain_xml.append(cert_xml)
        xml_output.append(cert_chain_xml)


        # Trust
        trust_validation_xml = Element('certificateValidation')

        # Hostname validation
        is_hostname_valid = 'False' if self.hostname_validation_result == X509_NAME_MISMATCH else 'True'
        host_validation_xml = Element('hostnameValidation', serverHostname=self.server_info.tls_server_name_indication,
                                      certificateMatchesServerHostname=is_hostname_valid)
        trust_validation_xml.append(host_validation_xml)

        # Path validation that was successful
        for path_result in self.path_validation_result_list:
            path_attrib_xml = {
                'usingTrustStore': path_result.trust_store.name,
                'trustStoreVersion': path_result.trust_store.version,
                'validationResult': path_result.verify_string
            }

            # EV certs - Only Mozilla supported for now
            if self.is_leaf_certificate_ev and 'Mozilla' in path_result.trust_store.name:
                path_attrib_xml['isExtendedValidationCertificate'] = str(self.is_leaf_certificate_ev)

            trust_validation_xml.append(Element('pathValidation', attrib=path_attrib_xml))


        # Path validation that ran into errors
        for path_error in self.path_validation_error_list:
            error_txt = 'ERROR: {}'.format(path_error.error_message)
            path_attrib_xml = {
                'usingTrustStore': path_result.trust_store.name,
                'trustStoreVersion': path_result.trust_store.version,
                'error': error_txt
            }

            trust_validation_xml.append(Element('pathValidation', attrib=path_attrib_xml))

        xml_output.append(trust_validation_xml)


        # OCSP Stapling
        ocsp_xml = Element('ocspStapling', attrib={'isSupported': 'False' if self.ocsp_response is None else 'True'})

        if self.ocsp_response:
            ocsp_resp_xmp = Element('ocspResponse',
                                    attrib={'isTrustedByMozillaCAStore': str(self.is_ocsp_response_trusted)})
            for (key, value) in self.ocsp_response.items():
                ocsp_resp_xmp.append(_keyvalue_pair_to_xml(key, value))

            ocsp_xml.append(ocsp_resp_xmp)
        xml_output.append(ocsp_xml)

        # All done
        return xml_output


class CertInfoBasicResult(CertInfoFullResult):
    """Same output as --certinfo_full except for the certificate text output.
    """

    def _get_certificate_text(self):
        """For --certinfo_basic, we only print a few specific fields of the certificate.
        """
        cert_dict = self.certificate_chain[0].as_dict

        # Extract the CN if there's one
        common_name = self._extract_subject_cn_or_oun(self.certificate_chain[0])

        try:
            # Extract the CN from the issuer if there's one
            issuer_name = unicode(cert_dict['issuer']['commonName'], 'utf-8')
        except KeyError:
            issuer_name = unicode(cert_dict['issuer'], 'utf-8')

        text_output = [
            self.FIELD_FORMAT("SHA1 Fingerprint:", self.certificate_chain[0].sha1_fingerprint),
            self.FIELD_FORMAT("Common Name:", common_name),
            self.FIELD_FORMAT("Issuer:", issuer_name),
            self.FIELD_FORMAT("Serial Number:", cert_dict['serialNumber']),
            self.FIELD_FORMAT("Not Before:", cert_dict['validity']['notBefore']),
            self.FIELD_FORMAT("Not After:", cert_dict['validity']['notAfter']),
            self.FIELD_FORMAT("Signature Algorithm:", cert_dict['signatureAlgorithm']),
            self.FIELD_FORMAT("Public Key Algorithm:", cert_dict['subjectPublicKeyInfo']['publicKeyAlgorithm']),
            self.FIELD_FORMAT("Key Size:", cert_dict['subjectPublicKeyInfo']['publicKeySize'])]

        try:
            # Print the Public key exponent if there's one; EC public keys don't have one for example
            text_output.append(self.FIELD_FORMAT("Exponent:", "{0} (0x{0:x})".format(
                int(cert_dict['subjectPublicKeyInfo']['publicKey']['exponent']))))
        except KeyError:
            pass

        try:
            # Print the SAN extension if there's one
            text_output.append(self.FIELD_FORMAT('X509v3 Subject Alternative Name:',
                                                 cert_dict['extensions']['X509v3 Subject Alternative Name']))
        except KeyError:
            pass

        return text_output


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

