# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import optparse
import os
from ssl import CertificateError
from xml.etree.ElementTree import Element

import binascii

import pickle

import cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from nassl.ocsp_response import OcspResponse
from nassl.ocsp_response import OcspResponseNotTrustedError
from nassl.ssl_client import ClientCertificateRequested
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.plugins.utils.certificate_utils import CertificateUtils
from sslyze.plugins.utils.trust_store.trust_store import TrustStore
from sslyze.plugins.utils.trust_store.trust_store import InvalidCertificateChainOrderError
from sslyze.plugins.utils.trust_store.trust_store import AnchorCertificateNotInTrustStoreError
from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.utils.thread_pool import ThreadPool
from typing import List
from typing import Optional
from typing import Text
from typing import Tuple


class CertificateInfoScanCommand(PluginScanCommand):
    """Verify the validity of the server(s) certificate(s) against various trust stores (Mozilla, Apple, etc.), and
    check for OCSP stapling support.
    """

    def __init__(self, ca_file=None):
        # type: (Optional[Text], Optional[bool]) -> None
        """

        Args:
            ca_file (Text): The path to a custom trust store file to use for certificate validation. The file should
                contain PEM-formatted root certificates.
        """
        super(CertificateInfoScanCommand, self).__init__()
        self.custom_ca_file = ca_file

    @classmethod
    def get_title(cls):
        return 'Certificate Information'

    @classmethod
    def get_cli_argument(cls):
        return 'certinfo'


class PathValidationResult(object):
    """The result of trying to validate a server's certificate chain using a specific trust store.

    Attributes:
        trust_store (TrustStore): The trust store used for validation.
        verify_string (Text): The string returned by OpenSSL's validation function.
        is_certificate_trusted (bool): Whether the certificate chain is trusted when using supplied the trust_store.
    """
    def __init__(self, trust_store, verify_string):
        # type: (TrustStore, Text) -> None
        self.trust_store = trust_store
        self.verify_string = verify_string
        self.is_certificate_trusted = True if verify_string == 'ok' else False


class PathValidationError(object):
    """An exception was raised while trying to validate a server's certificate using a specific trust store; should
    never happen.

    Attributes:
        trust_store (TrustStore): The trust store used for validation.
        error_message (Text): The exception that was raised formatted as a string.
    """
    def __init__(self, trust_store, exception):
        # type: (TrustStore, Exception) -> None
        self.trust_store = trust_store
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = '{} - {}'.format(str(exception.__class__.__name__), str(exception))


class CertificateInfoPlugin(plugin_base.Plugin):
    """Retrieve and validate the server(s)' certificate chain.
    """

    @classmethod
    def get_available_commands(cls):
        return [CertificateInfoScanCommand]

    @classmethod
    def get_cli_option_group(cls):
        options = super(CertificateInfoPlugin, cls).get_cli_option_group()

        # Add the special optional argument for this plugin's commands
        # They must match the names in the commands' contructor
        options.append(
            optparse.make_option(
                '--ca_file',
                help='Path to a local trust store file (with root certificates in PEM format) to verify the validity '
                     'of the server(s) certificate\'s chain(s) against.',
                dest='ca_file'
            )
        )
        return options


    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, CertificateInfoScanCommand) -> CertificateInfoScanResult
        final_trust_store_list = list(TrustStoresRepository.get_all())
        if scan_command.custom_ca_file:
            if not os.path.isfile(scan_command.custom_ca_file):
                raise ValueError('Could not open supplied CA file at "{}"'.format(scan_command.custom_ca_file))
            final_trust_store_list.append(TrustStore(scan_command.custom_ca_file, 'Custom --ca_file', 'N/A'))

        # Workaround for https://github.com/pyca/cryptography/issues/3495
        default_backend()

        thread_pool = ThreadPool()
        for trust_store in final_trust_store_list:
            # Try to connect with each trust store
            thread_pool.add_job((self._get_and_verify_certificate_chain, (server_info, trust_store)))

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
            raise last_exception

        # All done
        return CertificateInfoScanResult(server_info, scan_command, certificate_chain, path_validation_result_list,
                                         path_validation_error_list, ocsp_response)


    @staticmethod
    def _get_and_verify_certificate_chain(server_info, trust_store):
        # type: (ServerConnectivityInfo, TrustStore) -> Tuple[List[cryptography.x509.Certificate], Text, Optional[OcspResponse]]
        """Connects to the target server and uses the supplied trust store to validate the server's certificate.
        Returns the server's certificate and OCSP response.
        """
        ssl_connection = server_info.get_preconfigured_ssl_connection(ssl_verify_locations=trust_store.path)

        # Enable OCSP stapling
        ssl_connection.ssl_client.set_tlsext_status_ocsp()

        try:  # Perform the SSL handshake
            ssl_connection.connect()

            ocsp_response = ssl_connection.ssl_client.get_tlsext_status_ocsp_resp()
            x509_cert_chain = ssl_connection.ssl_client.get_peer_cert_chain()
            (_, verify_str) = ssl_connection.ssl_client.get_certificate_chain_verify_result()

        except ClientCertificateRequested:  # The server asked for a client cert
            # We can get the server cert anyway
            ocsp_response = ssl_connection.ssl_client.get_tlsext_status_ocsp_resp()
            x509_cert_chain = ssl_connection.ssl_client.get_peer_cert_chain()
            (_, verify_str) = ssl_connection.ssl_client.get_certificate_chain_verify_result()

        finally:
            ssl_connection.close()

        # Parse the certificates using the cryptography module
        parsed_x509_chain = [cryptography.x509.load_pem_x509_certificate(x509_cert.as_pem().encode('ascii'),
                                                                         backend=default_backend())
                             for x509_cert in x509_cert_chain]
        return parsed_x509_chain, verify_str, ocsp_response


class CertificateInfoScanResult(PluginScanResult):
    """The result of running a CertificateInfoScanCommand on a specific server.

    Attributes:
        certificate_chain (List[cryptography.x509.Certificate]): The certificate chain sent by the server; index 0 is 
            the leaf certificate. Each certificate is parsed using the cryptography module; documentation is available 
            at https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object. 
        path_validation_result_list (List[PathValidationResult]): The list of attempts at validating the server's
            certificate chain path using the trust stores packaged with SSLyze (Mozilla, Apple, etc.).
        path_validation_error_list (List[PathValidationError]):  The list of attempts at validating the server's
            certificate chain path that triggered an unexpected error.
        successful_trust_store (Optional[TrustStore]): The first trust store that successfully validated the server's
            certificate chain among all the trust stores packaged with SSLyze (Mozilla, Apple, Microsoft, etc.) as well
            as the custom store, if supplied using the ca_file option. This trust store is then used to build the
            server's verified certificate chain and to validate the OCSP response (if one is returned by the server).
            Will be None if none of the available trust stores were able to successfully validate the server's
            certificate chain.
        verified_certificate_chain (List[cryptography.x509.Certificate]): The verified certificate chain built using the
            successful_trust_store; index 0 is the leaf certificate and the last element is the anchor/CA certificate
            from the trust store. Will be empty if the validation failed with all available trust store, or the
            verified chain could not be built. Each certificate is parsed using the cryptography module; documentation 
            is available at https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object. 
        certificate_matches_hostname (bool): True if hostname validation was successful ie. the leaf certificate was
            issued for the server's hostname.
        is_leaf_certificate_ev (bool): True if the leaf certificate is Extended Validation according to Mozilla.
        ocsp_response (Optional[Dict[Text, Any]]): The OCSP response returned by the server. None if no response was
            sent by the server.
        is_ocsp_response_trusted (Optional[bool]): True if the OCSP response is trusted using the Mozilla trust store.
            None if no OCSP response was sent by the server.
        has_sha1_in_certificate_chain (bool): True if any of the leaf or intermediate certificates are signed using the
            SHA-1 algorithm. None if the verified chain could not be built or no HPKP header was returned.
        has_anchor_in_certificate_chain (bool): True if the server included the anchor/root certificate in the chain it
            send back to clients. None if the verified chain could not be built or no HPKP header was returned.
    """

    def __init__(
            self,
            server_info,                    # type: ServerConnectivityInfo
            scan_command,                   # type: CertificateInfoScanCommand
            certificate_chain,              # type: List[cryptography.x509.Certificate]
            path_validation_result_list,    # type: List[PathValidationResult]
            path_validation_error_list,     # type: List[PathValidationError]
            ocsp_response                   # type: OcspResponse
            ):
        # type: (...) -> None
        super(CertificateInfoScanResult, self).__init__(server_info, scan_command)
        # Find the first trust store that successfully validated the certificate chain
        self.successful_trust_store = None

        # Sort the path_validation_result_list so the same successful_trust_store always get picked for a given server
        # because threading timings change the order of path_validation_result_list
        def sort_function(path_validation):
            # type: (PathValidationResult) -> Text
            return path_validation.trust_store.name.lower()

        path_validation_result_list.sort(key=sort_function)
        for path_result in path_validation_result_list:
            if path_result.is_certificate_trusted:
                self.successful_trust_store = path_result.trust_store

        self.ocsp_response = None
        self.is_ocsp_response_trusted = None
        if ocsp_response:
            # We only keep the dictionary as a nassl.OcspResponse is not pickable
            self.ocsp_response = ocsp_response.as_dict()
            if self.successful_trust_store:
                try:
                    ocsp_response.verify(self.successful_trust_store.path)
                    self.is_ocsp_response_trusted = True
                except OcspResponseNotTrustedError:
                    self.is_ocsp_response_trusted = False

        self.certificate_chain = certificate_chain

        # Check if it is EV - we only have the EV OIDs for Mozilla
        self.is_leaf_certificate_ev = TrustStoresRepository.get_main().is_extended_validation(self.certificate_chain[0])

        # Try to build the verified chain
        self.verified_certificate_chain = []
        self.is_certificate_chain_order_valid = True
        if self.successful_trust_store:
            try:
                self.verified_certificate_chain = self.successful_trust_store.build_verified_certificate_chain(
                    self.certificate_chain
                )
            except InvalidCertificateChainOrderError:
                self.is_certificate_chain_order_valid = False
            except AnchorCertificateNotInTrustStoreError:
                pass

        self.has_anchor_in_certificate_chain = None
        if self.verified_certificate_chain:
            self.has_anchor_in_certificate_chain = self.verified_certificate_chain[-1] in self.certificate_chain

        self.path_validation_result_list = path_validation_result_list
        self.path_validation_error_list = path_validation_error_list
        try:
            CertificateUtils.matches_hostname(certificate_chain[0], server_info.tls_server_name_indication)
            self.certificate_matches_hostname = True
        except CertificateError:
            self.certificate_matches_hostname = False

        # Check if a SHA1-signed certificate is in the chain
        # Root certificates can still be signed with SHA1 so we only check leaf and intermediate certificates
        self.has_sha1_in_certificate_chain = None
        if self.verified_certificate_chain:
            self.has_sha1_in_certificate_chain = False
            for cert in self.verified_certificate_chain[:-1]:
                if isinstance(cert.signature_hash_algorithm, hashes.SHA1):
                    self.has_sha1_in_certificate_chain = True
                    break

    def __getstate__(self):
        # This object needs to be pick-able as it gets sent through multiprocessing.Queues
        pickable_dict = self.__dict__.copy()
        # Manually handle non-pickable entries
        pickable_dict['successful_trust_store'] = pickle.dumps(pickable_dict['successful_trust_store'])
        pickable_dict['path_validation_result_list'] = pickle.dumps(pickable_dict['path_validation_result_list'])

        pem_certificate_chain = [cert.public_bytes(Encoding.PEM) for cert in pickable_dict['certificate_chain']]
        pickable_dict['certificate_chain'] = pem_certificate_chain

        pem_verified_chain = [cert.public_bytes(Encoding.PEM) for cert in pickable_dict['verified_certificate_chain']]
        pickable_dict['verified_certificate_chain'] = pem_verified_chain
        return pickable_dict

    def __setstate__(self, state):
        self.__dict__.update(state)
        # Manually restore non-pickable entries
        self.__dict__['successful_trust_store'] = pickle.loads(self.__dict__['successful_trust_store'])
        self.__dict__['path_validation_result_list'] = pickle.loads(self.__dict__['path_validation_result_list'])

        certificate_chain = [cryptography.x509.load_pem_x509_certificate(cert_pem, default_backend())
                             for cert_pem in self.__dict__['certificate_chain']]
        self.__dict__['certificate_chain'] = certificate_chain

        verified_chain = [cryptography.x509.load_pem_x509_certificate(cert_pem, default_backend())
                          for cert_pem in self.__dict__['verified_certificate_chain']]
        self.__dict__['verified_certificate_chain'] = verified_chain

    TRUST_FORMAT = '{store_name} CA Store ({store_version}):'
    NO_VERIFIED_CHAIN_ERROR_TXT = 'ERROR - Could not build verified chain (certificate untrusted?)'

    def as_text(self):
        text_output = [self._format_title(self.scan_command.get_title())]
        text_output.append(self._format_subtitle('Content'))
        text_output.extend(self._get_basic_certificate_text())

        # Trust section
        text_output.extend(['', self._format_subtitle('Trust')])

        # Hostname validation
        server_name_indication = self.server_info.tls_server_name_indication
        if self.server_info.tls_server_name_indication != self.server_info.hostname:
            text_output.append(self._format_field("SNI enabled with virtual domain:", server_name_indication))

        hostname_validation_text = 'OK - Certificate matches {hostname}'.format(hostname=server_name_indication) \
            if self.certificate_matches_hostname \
            else 'FAILED - Certificate does NOT match {hostname}'.format(hostname=server_name_indication)
        text_output.append(self._format_field('Hostname Validation:', hostname_validation_text))

        # Path validation that was successfully tested
        for path_result in self.path_validation_result_list:
            if path_result.is_certificate_trusted:
                # EV certs - Only Mozilla supported for now
                ev_txt = ''
                if self.is_leaf_certificate_ev and TrustStoresRepository.get_main() == path_result.trust_store:
                    ev_txt = ', Extended Validation'
                path_txt = 'OK - Certificate is trusted{}'.format(ev_txt)

            else:
                path_txt = 'FAILED - Certificate is NOT Trusted: {}'.format(path_result.verify_string)

            text_output.append(self._format_field(
                self.TRUST_FORMAT.format(store_name=path_result.trust_store.name,
                                         store_version=path_result.trust_store.version),
                path_txt))

        # Path validation that ran into errors
        for path_error in self.path_validation_error_list:
            error_txt = 'ERROR: {}'.format(path_error.error_message)
            text_output.append(self._format_field(
                self.TRUST_FORMAT.format(store_name=path_result.trust_store.name,
                                         store_version=path_result.trust_store.version),
                error_txt))

        # Print the Common Names within the certificate chain
        cns_in_certificate_chain = [CertificateUtils.get_name_as_short_text(cert.subject)
                                    for cert in self.certificate_chain]
        text_output.append(self._format_field('Received Chain:', ' --> '.join(cns_in_certificate_chain)))

        # Print the Common Names within the verified certificate chain if validation was successful
        if self.verified_certificate_chain:
            cns_in_certificate_chain = [CertificateUtils.get_name_as_short_text(cert.subject)
                                        for cert in self.verified_certificate_chain]
            verified_chain_txt = ' --> '.join(cns_in_certificate_chain)
        else:
            verified_chain_txt = self.NO_VERIFIED_CHAIN_ERROR_TXT
        text_output.append(self._format_field('Verified Chain:', verified_chain_txt))

        if self.verified_certificate_chain:
            chain_with_anchor_txt = 'OK - Anchor certificate not sent' if not self.has_anchor_in_certificate_chain \
                else 'WARNING - Received certificate chain contains the anchor certificate'
        else:
            chain_with_anchor_txt = self.NO_VERIFIED_CHAIN_ERROR_TXT
        text_output.append(self._format_field('Received Chain Contains Anchor:', chain_with_anchor_txt))

        chain_order_txt = 'OK - Order is valid' if self.is_certificate_chain_order_valid \
            else 'FAILED - Certificate chain out of order!'
        text_output.append(self._format_field('Received Chain Order:', chain_order_txt))

        if self.verified_certificate_chain:
            sha1_text = 'OK - No SHA1-signed certificate in the verified certificate chain' \
                if not self.has_sha1_in_certificate_chain \
                else 'INSECURE - SHA1-signed certificate in the verified certificate chain'
        else:
            sha1_text = self.NO_VERIFIED_CHAIN_ERROR_TXT

        text_output.append(self._format_field('Verified Chain contains SHA1:', sha1_text))

        # OCSP stapling
        text_output.extend(['', self._format_subtitle('OCSP Stapling')])

        if self.ocsp_response is None:
            text_output.append(self._format_field('', 'NOT SUPPORTED - Server did not send back an OCSP response.'))

        else:
            ocsp_trust_txt = 'OK - Response is trusted' \
                if self.is_ocsp_response_trusted \
                else 'FAILED - Response is NOT trusted'

            ocsp_resp_txt = [
                self._format_field('OCSP Response Status:', self.ocsp_response['responseStatus']),
                self._format_field('Validation w/ Mozilla Store:', ocsp_trust_txt),
                self._format_field('Responder Id:', self.ocsp_response['responderID'])]

            if 'successful' in self.ocsp_response['responseStatus']:
                ocsp_resp_txt.extend([
                    self._format_field('Cert Status:', self.ocsp_response['responses'][0]['certStatus']),
                    self._format_field('Cert Serial Number:',
                                       self.ocsp_response['responses'][0]['certID']['serialNumber']),
                    self._format_field('This Update:', self.ocsp_response['responses'][0]['thisUpdate']),
                    self._format_field('Next Update:', self.ocsp_response['responses'][0]['nextUpdate'])
                ])
            text_output.extend(ocsp_resp_txt)

        # All done
        return text_output

    @staticmethod
    def _certificate_chain_to_xml(certificate_chain):
        # type: (List[cryptography.x509.Certificate]) -> List[Element]
        cert_xml_list = []
        for certificate in certificate_chain:
            cert_xml = Element('certificate', attrib={
                'sha1Fingerprint': binascii.hexlify(certificate.fingerprint(hashes.SHA1())).decode('ascii'),
                'hpkpSha256Pin': CertificateUtils.get_hpkp_pin(certificate)
            })

            # Add the PEM cert
            cert_as_pem_xml = Element('asPEM')
            cert_as_pem_xml.text = certificate.public_bytes(Encoding.PEM).decode('ascii')
            cert_xml.append(cert_as_pem_xml)

            # Add some of the fields of the cert
            elem_xml = Element('subject')
            elem_xml.text = CertificateUtils.get_name_as_text(certificate.subject)
            cert_xml.append(elem_xml)

            elem_xml = Element('issuer')
            elem_xml.text = CertificateUtils.get_name_as_text(certificate.issuer)
            cert_xml.append(elem_xml)

            elem_xml = Element('serialNumber')
            elem_xml.text = str(certificate.serial_number)
            cert_xml.append(elem_xml)

            elem_xml = Element('notBefore')
            elem_xml.text = certificate.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
            cert_xml.append(elem_xml)

            elem_xml = Element('notAfter')
            elem_xml.text = certificate.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")
            cert_xml.append(elem_xml)

            elem_xml = Element('signatureAlgorithm')
            elem_xml.text = certificate.signature_hash_algorithm.name
            cert_xml.append(elem_xml)

            key_attrs = {'algorithm': CertificateUtils.get_public_key_type(certificate)}
            public_key = certificate.public_key()
            if isinstance(public_key, EllipticCurvePublicKey):
                key_attrs['size'] = str(public_key.curve.key_size)
                key_attrs['curve'] =  public_key.curve.name
            else:
                key_attrs['size'] = str(public_key.key_size)
                key_attrs['exponent'] = str(public_key.public_numbers().e)

            elem_xml = Element('publicKey', attrib=key_attrs)
            cert_xml.append(elem_xml)

            cert_xml_list.append(cert_xml)
        return cert_xml_list

    def as_xml(self):
        xml_output = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())

        # Certificate chain
        cert_chain_attrs = {
            'isChainOrderValid': str(self.is_certificate_chain_order_valid),
            'suppliedServerNameIndication': self.server_info.tls_server_name_indication,
            'containsAnchorCertificate': str(False) if not self.has_anchor_in_certificate_chain else str(True)
        }
        cert_chain_xml = Element('receivedCertificateChain', attrib=cert_chain_attrs)
        for cert_xml in self._certificate_chain_to_xml(self.certificate_chain):
            cert_chain_xml.append(cert_xml)
        xml_output.append(cert_chain_xml)

        # Trust
        trust_validation_xml = Element('certificateValidation')

        # Hostname validation
        host_validation_xml = Element('hostnameValidation', serverHostname=self.server_info.tls_server_name_indication,
                                      certificateMatchesServerHostname=str(self.certificate_matches_hostname))
        trust_validation_xml.append(host_validation_xml)

        # Path validation that was successful
        for path_result in self.path_validation_result_list:
            path_attrib_xml = {
                'usingTrustStore': path_result.trust_store.name,
                'trustStoreVersion': path_result.trust_store.version,
                'validationResult': path_result.verify_string
            }

            # Things we only do with the Mozilla store: EV certs
            if self.is_leaf_certificate_ev and TrustStoresRepository.get_main() == path_result.trust_store:
                path_attrib_xml['isExtendedValidationCertificate'] = str(self.is_leaf_certificate_ev)

            path_valid_xml = Element('pathValidation', attrib=path_attrib_xml)
            trust_validation_xml.append(path_valid_xml)

        # Path validation that ran into errors
        for path_error in self.path_validation_error_list:
            error_txt = 'ERROR: {}'.format(path_error.error_message)
            path_attrib_xml = {
                'usingTrustStore': path_result.trust_store.name,
                'trustStoreVersion': path_result.trust_store.version,
                'error': error_txt
            }
            trust_validation_xml.append(Element('pathValidation', attrib=path_attrib_xml))

        # Verified chain
        if self.verified_certificate_chain:
            verified_cert_chain_xml = Element(
                'verifiedCertificateChain',
                {'hasSha1SignedCertificate': str(self.has_sha1_in_certificate_chain),
                 'suppliedServerNameIndication': self.server_info.tls_server_name_indication,
                 'successfulTrustStore': self.successful_trust_store.name}
            )
            for cert_xml in self._certificate_chain_to_xml(self.verified_certificate_chain):
                verified_cert_chain_xml.append(cert_xml)
            trust_validation_xml.append(verified_cert_chain_xml)

        xml_output.append(trust_validation_xml)


        # OCSP Stapling
        ocsp_xml = Element('ocspStapling', attrib={'isSupported': 'False' if self.ocsp_response is None else 'True'})

        if self.ocsp_response:
            ocsp_resp_xmp = Element('ocspResponse',
                                    attrib={'isTrustedByMozillaCAStore': str(self.is_ocsp_response_trusted)})

            responder_xml = Element('responderID')
            responder_xml.text = self.ocsp_response['responderID']
            ocsp_resp_xmp.append(responder_xml)

            produced_xml = Element('producedAt')
            produced_xml.text = self.ocsp_response['producedAt']
            ocsp_resp_xmp.append(produced_xml)

            response_status_xml = Element('responseStatus')
            response_status_xml.text = self.ocsp_response['responseStatus']
            ocsp_resp_xmp.append(response_status_xml)

            ocsp_xml.append(ocsp_resp_xmp)
        xml_output.append(ocsp_xml)

        # All done
        return xml_output

    def _get_basic_certificate_text(self):
        certificate = self.certificate_chain[0]
        public_key = self.certificate_chain[0].public_key()
        text_output = [
            self._format_field('SHA1 Fingerprint:',
                               binascii.hexlify(certificate.fingerprint(hashes.SHA1())).decode('ascii')),
            self._format_field('Common Name:', CertificateUtils.get_name_as_short_text(certificate.subject)),
            self._format_field('Issuer:', CertificateUtils.get_name_as_short_text(certificate.issuer)),
            self._format_field('Serial Number:', certificate.serial_number),
            self._format_field('Not Before:', certificate.not_valid_before),
            self._format_field('Not After:', certificate.not_valid_after),
            self._format_field('Signature Algorithm:', certificate.signature_hash_algorithm.name),
            self._format_field('Public Key Algorithm:', CertificateUtils.get_public_key_type(certificate))]

        if isinstance(public_key, EllipticCurvePublicKey):
            text_output.append(self._format_field('Key Size:', public_key.curve.key_size))
            text_output.append(self._format_field('Curve:', public_key.curve.name))
        else:
            text_output.append(self._format_field('Key Size:', public_key.key_size))
            text_output.append(self._format_field('Exponent:', '{0} (0x{0:x})'.format(public_key.public_numbers().e)))

        try:
            # Print the SAN extension if there's one
            text_output.append(self._format_field('DNS Subject Alternative Names:',
                                                  str(CertificateUtils.get_dns_subject_alternative_names(certificate))))
        except KeyError:
            pass

        return text_output
