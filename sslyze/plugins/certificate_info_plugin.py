import optparse
import os
from datetime import datetime
from enum import Enum
from ssl import CertificateError
from xml.etree.ElementTree import Element

import binascii

import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509 import Certificate, load_pem_x509_certificate
from nassl.ocsp_response import OcspResponse, OcspResponseStatusEnum
from nassl.ocsp_response import OcspResponseNotTrustedError
from nassl.ssl_client import ClientCertificateRequested
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.plugins.utils.certificate_utils import CertificateUtils
from sslyze.plugins.utils.trust_store.trust_store import TrustStore
from sslyze.plugins.utils.trust_store.trust_store import InvalidCertificateChainOrderError
from sslyze.plugins.utils.trust_store.trust_store import AnchorCertificateNotInTrustStoreError
from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.utils.thread_pool import ThreadPool
from typing import List, Dict, Any, Type
from typing import Optional
from typing import Tuple


class CertificateInfoScanCommand(PluginScanCommand):
    """Verify the validity of the server(s) certificate(s) against various trust stores (Mozilla, Apple, etc.), and
    check for OCSP stapling support.
    """

    def __init__(self, ca_file: Optional[str] = None) -> None:
        """

        Args:
            ca_file: The path to a custom trust store file to use for certificate validation. The file should contain
                PEM-formatted root certificates.
        """
        super().__init__()
        self.custom_ca_file = ca_file

    @classmethod
    def get_title(cls) -> str:
        return 'Certificate Information'

    @classmethod
    def get_cli_argument(cls) -> str:
        return 'certinfo'


class PathValidationResult:
    """The result of trying to validate a server's certificate chain using a specific trust store.

    Attributes:
        trust_store (TrustStore): The trust store used for validation.
        verify_string (Text): The string returned by OpenSSL's validation function.
        is_certificate_trusted (bool): Whether the certificate chain is trusted when using supplied the trust_store.
    """
    def __init__(self, trust_store: TrustStore, verify_string: str) -> None:
        self.trust_store = trust_store
        self.verify_string = verify_string
        self.is_certificate_trusted = True if verify_string == 'ok' else False


class PathValidationError:
    """An exception was raised while trying to validate a server's certificate using a specific trust store; should
    never happen.

    Attributes:
        trust_store (TrustStore): The trust store used for validation.
        error_message (Text): The exception that was raised formatted as a string.
    """
    def __init__(self, trust_store: TrustStore, exception: Exception) -> None:
        self.trust_store = trust_store
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = '{} - {}'.format(str(exception.__class__.__name__), str(exception))


class CertificateInfoPlugin(plugin_base.Plugin):
    """Retrieve and validate the server(s)' certificate chain.
    """

    @classmethod
    def get_available_commands(cls) -> List[Type[PluginScanCommand]]:
        return [CertificateInfoScanCommand]

    @classmethod
    def get_cli_option_group(cls) -> List[optparse.Option]:
        options = super().get_cli_option_group()

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

    def process_task(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: PluginScanCommand
    ) -> 'CertificateInfoScanResult':
        if not isinstance(scan_command, CertificateInfoScanCommand):
            raise ValueError('Unexpected scan command')

        final_trust_store_list = TrustStoresRepository.get_default().get_all_stores()
        if scan_command.custom_ca_file:
            if not os.path.isfile(scan_command.custom_ca_file):
                raise ValueError('Could not open supplied CA file at "{}"'.format(scan_command.custom_ca_file))
            final_trust_store_list.append(TrustStore(scan_command.custom_ca_file, 'Custom --ca_file', 'N/A'))

        # Workaround for https://github.com/pyca/cryptography/issues/3495
        default_backend()

        thread_pool = ThreadPool()
        for trust_store in final_trust_store_list:
            # Try to connect with each trust store
            thread_pool.add_job((self._get_and_verify_certificate_chain, [server_info, trust_store]))

        # Start processing the jobs; one thread per trust
        thread_pool.start(len(final_trust_store_list))

        # Store the results as they come
        certificate_chain: List[Certificate] = []
        path_validation_result_list = []
        path_validation_error_list = []
        ocsp_response = None

        for (job, result) in thread_pool.get_result():
            (_, (_, trust_store)) = job
            certificate_chain, validation_result, _ocsp_response = result

            # Keep the OCSP response if the validation was succesful and a response was returned
            if _ocsp_response:
                ocsp_response = _ocsp_response

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
            raise last_exception  # type: ignore

        # All done
        return CertificateInfoScanResult(server_info, scan_command, certificate_chain, path_validation_result_list,
                                         path_validation_error_list, ocsp_response)

    @staticmethod
    def _get_and_verify_certificate_chain(
            server_info: ServerConnectivityInfo,
            trust_store: TrustStore
    ) -> Tuple[List[Certificate], str, Optional[OcspResponse]]:
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
        parsed_x509_chain = [load_pem_x509_certificate(x509_cert.as_pem().encode('ascii'), backend=default_backend())
                             for x509_cert in x509_cert_chain]
        return parsed_x509_chain, verify_str, ocsp_response


# TODO(AD): Rename some of the attributes to make the naming consistent (is_cert_xxx VS cert_is_xxx)
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
        certificate_has_must_staple_extension (bool): True if the leaf certificate has the OCSP Must-Staple
            extension as defined in RFC 6066.
        certificate_included_scts_count (Optional[int]): The number of Signed Certificate Timestamps (SCTs) for
            Certificate Transparency embedded in the leaf certificate. None if the version of OpenSSL installed on the
            system is too old to be able to parse the SCT extension.
        ocsp_response (Optional[Dict[Text, Any]]): The OCSP response returned by the server. None if no response was
            sent by the server.
        ocsp_response_status (Optional[OcspResponseStatusEnum]): The status of the OCSP response returned by the server.
            None if no response was sent by the server.
        is_ocsp_response_trusted (Optional[bool]): True if the OCSP response is trusted using the Mozilla trust store.
            None if no OCSP response was sent by the server.
        has_sha1_in_certificate_chain (bool): True if any of the leaf or intermediate certificates are signed using the
            SHA-1 algorithm. None if the verified chain could not be built.
        has_anchor_in_certificate_chain (bool): True if the server included the anchor/root certificate in the chain it
            send back to clients. None if the verified chain could not be built.
        symantec_distrust_timeline (Optional[SymantecDistrustTimelineEnum]): When the certificate will be distrusted
            in Chrome and Firefox
            (https://blog.qualys.com/ssllabs/2017/09/26/google-and-mozilla-deprecating-existing-symantec-certificates).
            None if the certificate chain was not issued by one of the Symantec CAs.
    """

    def __init__(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: CertificateInfoScanCommand,
            certificate_chain: List[Certificate],
            path_validation_result_list: List[PathValidationResult],
            path_validation_error_list: List[PathValidationError],
            ocsp_response: OcspResponse
    ) -> None:
        super().__init__(server_info, scan_command)
        # Find the first trust store that successfully validated the certificate chain
        self.successful_trust_store = None

        # Sort the path_validation_result_list so the same successful_trust_store always get picked for a given server
        # because threading timings change the order of path_validation_result_list
        def sort_function(path_validation: PathValidationResult) -> str:
            return path_validation.trust_store.name.lower()

        path_validation_result_list.sort(key=sort_function)
        for path_result in path_validation_result_list:
            if path_result.is_certificate_trusted:
                self.successful_trust_store = path_result.trust_store

        self.ocsp_response = None
        self.is_ocsp_response_trusted = None
        self.ocsp_response_status = None
        if ocsp_response:
            self.ocsp_response_status = ocsp_response.status
            # We only keep the dictionary as a nassl.OcspResponse is not pickable
            self.ocsp_response = ocsp_response.as_dict()
            if self.successful_trust_store and self.ocsp_response_status == OcspResponseStatusEnum.SUCCESSFUL:
                try:
                    ocsp_response.verify(self.successful_trust_store.path)
                    self.is_ocsp_response_trusted = True
                except OcspResponseNotTrustedError:
                    self.is_ocsp_response_trusted = False

        self.certificate_chain = certificate_chain

        # Check if it is EV - we only have the EV OIDs for Mozilla
        self.is_leaf_certificate_ev = TrustStoresRepository.get_default().get_main_store().is_extended_validation(
            self.certificate_chain[0]
        )

        # Look for the Must-Staple extension
        has_must_staple = CertificateUtils.has_ocsp_must_staple_extension(self.certificate_chain[0])
        self.certificate_has_must_staple_extension = has_must_staple

        # Look for the certificate transparency extension
        self.certificate_included_scts_count = CertificateUtils.count_scts_in_sct_extension(self.certificate_chain[0])

        # Try to build the verified chain
        self.verified_certificate_chain: List[Certificate] = []
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

        # Check if this is a distrusted Symantec-issued chain
        self.symantec_distrust_timeline = _SymantecDistructTester.get_distrust_timeline(self.verified_certificate_chain)

    def __getstate__(self) -> Dict[str, Any]:
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

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        # Manually restore non-pickable entries
        self.__dict__['successful_trust_store'] = pickle.loads(self.__dict__['successful_trust_store'])
        self.__dict__['path_validation_result_list'] = pickle.loads(self.__dict__['path_validation_result_list'])

        certificate_chain = [load_pem_x509_certificate(cert_pem, default_backend())
                             for cert_pem in self.__dict__['certificate_chain']]
        self.__dict__['certificate_chain'] = certificate_chain

        verified_chain = [load_pem_x509_certificate(cert_pem, default_backend())
                          for cert_pem in self.__dict__['verified_certificate_chain']]
        self.__dict__['verified_certificate_chain'] = verified_chain

    TRUST_FORMAT = '{store_name} CA Store ({store_version}):'
    NO_VERIFIED_CHAIN_ERROR_TXT = 'ERROR - Could not build verified chain (certificate untrusted?)'

    def as_text(self) -> List[str]:
        text_output = [self._format_title(self.scan_command.get_title()), self._format_subtitle('Content')]
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
                if self.is_leaf_certificate_ev and path_result.trust_store.ev_oids:
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
                self.TRUST_FORMAT.format(
                    store_name=path_error.trust_store.name,
                    store_version=path_error.trust_store.version
                ),
                error_txt))

        if self.symantec_distrust_timeline is not None:
            timeline_str = 'March 2018' if self.symantec_distrust_timeline == SymantecDistrustTimelineEnum.MARCH_2018 \
                else 'September 2018'
            symantec_str = 'WARNING: Certificate distrusted by Google and Mozilla on {}'.format(timeline_str)
        else:
            symantec_str = 'OK - Not a Symantec-issued certificate'
        text_output.append(self._format_field('Symantec 2018 Deprecation:', symantec_str))

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

        # Extensions section
        text_output.extend(['', self._format_subtitle('Extensions')])

        # OCSP must-staple
        must_staple_txt = 'OK - Extension present' \
            if self.certificate_has_must_staple_extension \
            else 'NOT SUPPORTED - Extension not found'
        text_output.append(self._format_field('OCSP Must-Staple:', must_staple_txt))

        # Look for SCT extension
        scts_count = self.certificate_included_scts_count
        if scts_count is None:
            sct_txt = 'OK - Extension present'
        elif scts_count == 0:
            sct_txt = 'NOT SUPPORTED - Extension not found'
        elif scts_count < 3:
            sct_txt = 'WARNING - Only {} SCTs included but Google recommends 3 or more'.format(str(scts_count))
        else:
            sct_txt = 'OK - {} SCTs included'.format(str(scts_count))
        text_output.append(self._format_field('Certificate Transparency:', sct_txt))

        # OCSP stapling
        text_output.extend(['', self._format_subtitle('OCSP Stapling')])

        if self.ocsp_response is None:
            text_output.append(self._format_field('', 'NOT SUPPORTED - Server did not send back an OCSP response'))

        else:
            if self.ocsp_response_status != OcspResponseStatusEnum.SUCCESSFUL:
                ocsp_resp_txt = [self._format_field('', 'ERROR - OCSP response status is not successful: {}'.format(
                    self.ocsp_response_status.name  # type: ignore
                ))]
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
    def _certificate_chain_to_xml(certificate_chain: List[Certificate]) -> List[Element]:
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
                key_attrs['curve'] = public_key.curve.name
            else:
                key_attrs['size'] = str(public_key.key_size)
                key_attrs['exponent'] = str(public_key.public_numbers().e)

            elem_xml = Element('publicKey', attrib=key_attrs)
            cert_xml.append(elem_xml)

            dns_alt_names = CertificateUtils.get_dns_subject_alternative_names(certificate)
            if dns_alt_names:
                san_xml = Element('subjectAlternativeName')
                for dns_name in dns_alt_names:
                    dns_xml = Element('DNS')
                    dns_xml.text = dns_name
                    san_xml.append(dns_xml)
                cert_xml.append(san_xml)

            cert_xml_list.append(cert_xml)
        return cert_xml_list

    def as_xml(self) -> Element:
        xml_output = Element(self.scan_command.get_cli_argument(), title=self.scan_command.get_title())

        # Certificate chain
        cert_chain_attrs = {
            'isChainOrderValid': str(self.is_certificate_chain_order_valid),
            'suppliedServerNameIndication': self.server_info.tls_server_name_indication,
            'containsAnchorCertificate': str(False) if not self.has_anchor_in_certificate_chain else str(True),
            'hasMustStapleExtension': str(self.certificate_has_must_staple_extension),
            'includedSctsCount': str(self.certificate_included_scts_count),
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
            if self.is_leaf_certificate_ev and path_result.trust_store.ev_oids:
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
                {
                    'hasSha1SignedCertificate': str(self.has_sha1_in_certificate_chain),
                    'suppliedServerNameIndication': self.server_info.tls_server_name_indication,
                    'successfulTrustStore': self.successful_trust_store.name,  # type: ignore
                    'hasMustStapleExtension': str(self.certificate_has_must_staple_extension),
                    'includedSctsCount': str(self.certificate_included_scts_count),
                    'isAffectedBySymantecDeprecation': str(True if self.symantec_distrust_timeline else False)
                }
            )
            for cert_xml in self._certificate_chain_to_xml(self.verified_certificate_chain):
                verified_cert_chain_xml.append(cert_xml)
            trust_validation_xml.append(verified_cert_chain_xml)

        xml_output.append(trust_validation_xml)

        # OCSP Stapling
        ocsp_xml = Element('ocspStapling', attrib={'isSupported': 'False' if self.ocsp_response is None else 'True'})

        if self.ocsp_response is not None:
            if self.ocsp_response_status != OcspResponseStatusEnum.SUCCESSFUL:
                ocsp_resp_xmp = Element('ocspResponse',
                                        attrib={
                                            'status': self.ocsp_response_status.name  # type: ignore
                                        })
            else:
                ocsp_resp_xmp = Element('ocspResponse',
                                        attrib={
                                            'isTrustedByMozillaCAStore': str(self.is_ocsp_response_trusted),
                                            'status': self.ocsp_response_status.name  # type: ignore
                                        })

                responder_xml = Element('responderID')
                responder_xml.text = self.ocsp_response['responderID']
                ocsp_resp_xmp.append(responder_xml)

                produced_xml = Element('producedAt')
                produced_xml.text = self.ocsp_response['producedAt']
                ocsp_resp_xmp.append(produced_xml)

            ocsp_xml.append(ocsp_resp_xmp)
        xml_output.append(ocsp_xml)

        # All done
        return xml_output

    def _get_basic_certificate_text(self) -> List[str]:
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
        elif isinstance(public_key, RSAPublicKey):
            text_output.append(self._format_field('Key Size:', public_key.key_size))
            text_output.append(self._format_field('Exponent:', '{0} (0x{0:x})'.format(public_key.public_numbers().e)))
        else:
            # DSA Key? https://github.com/nabla-c0d3/sslyze/issues/314
            pass

        try:
            # Print the SAN extension if there's one
            text_output.append(self._format_field('DNS Subject Alternative Names:',
                                                  str(CertificateUtils.get_dns_subject_alternative_names(certificate))))
        except KeyError:
            pass

        return text_output


class SymantecDistrustTimelineEnum(Enum):
    MARCH_2018 = 1
    SEPTEMBER_2018 = 2


class _SymantecDistructTester:
    """Logic to detect Synmantec certificates, to be distrusted by Google and Mozilla.

    https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html
    """

    # Taken from https://cs.chromium.org/chromium/src/net/cert/symantec_certs.cc
    _CA_KEYS_BLACKLIST = [
        # kSymantecRoots
        '023c81cce8e7c64fa942d3c15048707d35d9bb5b87f4f544c5bf1bc5643af2fa',
        '0999bf900bd5c297865e21e1aade6cf6bb3a94d11ae5ea798442a4e2f813241f',
        '0bdd5abe940caaabe8b2bba88348fb6f4aa4cc84436f880bece66b48bda913d8',
        '16a9e012d32329f282b10bbf57c7c0b42ae80f6ac9542eb409bc1c2cde50d322',
        '17755a5c295f3d2d72e6f031a1f07f400c588b9e582b22f17eae31a1590d1185',
        '1906c6124dbb438578d00e066d5054c6c37f0fa6028c05545e0994eddaec8629',
        '1916f3508ec3fad795f8dc4bd316f9c6085a64de3c4153ac6d62d5ea19515d39',
        '1d75d0831b9e0885394d32c7a1bfdb3dbc1c28e2b0e8391fb135981dbc5ba936',
        '22076e5aef44bb9a416a28b7d1c44322d7059f60feffa5caf6c5be8447891303',
        '25b41b506e4930952823a6eb9f1d31def645ea38a5c6c6a96d71957e384df058',
        '26c18dc6eea6f632f676bceba1d8c2b48352f29c2d5fcda878e09dcb832dd6e5',
        '2dc9470be63ef4acf1bd828609402bb7b87bd99638a643934e88682d1be8c308',
        '2dee5171596ab8f3cd3c7635fea8e6c3006aa9e31db39d03a7480ddb2428a33e',
        '3027a298fa57314dc0e3dd1019411b8f404c43c3f934ce3bdf856512c80aa15c',
        '31512680233f5f2a1f29437f56d4988cf0afc41cc6c5da6275928e9c0beade27',
        '43b3107d7342165d406cf975cd79b36ed1645048f05d7ff6ea0096e427b7db84',
        '463dbb9b0a26ed2616397b643125fbd29b66cf3a46fdb4384b209e78237a1aff',
        '479d130bf3fc61dc2f1d508d239a13276ae7b3c9841011a02c1402c7e677bd5f',
        '4905466623ab4178be92ac5cbd6584f7a1e17f27652d5a85af89504ea239aaaa',
        '495a96ba6bad782407bd521a00bace657bb355555e4bb7f8146c71bba57e7ace',
        '4ba6031ca305b09e53bde3705145481d0332b651fe30370dd5254cc4d2cb32f3',
        '5192438ec369d7ee0ce71f5c6db75f941efbf72e58441715e99eab04c2c8acee',
        '567b8211fd20d3d283ee0cd7ce0672cb9d99bc5b487a58c9d54ec67f77d4a8f5',
        '5c4f285388f38336269a55c7c12c0b3ca73fef2a5a4df82b89141e841a6c4de4',
        '67dc4f32fa10e7d01a79a073aa0c9e0212ec2ffc3d779e0aa7f9c0f0e1c2c893',
        '6b86de96a658a56820a4f35d90db6c3efdd574ce94b909cb0d7ff17c3c189d83',
        '7006a38311e58fb193484233218210c66125a0e4a826aed539ac561dfbfbd903',
        '781f1c3a6a42e3e915222db4967702a2e577aeb017075fa3c159851fddd0535e',
        '7caa03465124590c601e567e52148e952c0cffe89000530fe0d95b6d50eaae41',
        '809f2baae35afb4f36bd6476ce75c2001077901b6af5c4dab82e188c6b95c1a1',
        '81a98fc788c35f557645a95224e50cd1dac8ffb209dc1e5688aa29205f132218',
        '860a7f19210d5ead057a78532b80951453cb2907315f3ba7aa47b69897d70f3f',
        '87af34d66fb3f2fdf36e09111e9aba2f6f44b207f3863f3d0b54b25023909aa5',
        '95735473bd67a3b95a8d5f90c5a21ace1e0d7947320674d4ab847972b91544d2',
        '967b0cd93fcef7f27ce2c245767ae9b05a776b0649f9965b6290968469686872',
        '9699225c5de52e]]56cdd32df2e96d1cfea5aa3ca0bb52cd8933c23b5c27443820',
        '9c6f6a123cbaa4ee34dbeceee24c97d738878cb423f3c2273903424f5d1f6dd5',
        'a6f1f9bf8a0a9ddc080fb49b1efc3d1a1c2c32dc0e136a5b00c97316f2a3dc11',
        'ab3876c3da5de0c9cf6736868ee5b88bf9ba1dff9c9d72d2fe5a8d2f78302166',
        'ab39a4b025955691a40269f353fa1d5cb94eaf6c7ea9808484bbbb62fd9f68f3',
        'ab5cdb3356397356d6e691973c25b8618b65d76a90486ea7a8a5c17767f4673a',
        'ab98495276adf1ecaff28f35c53048781e5c1718dab9c8e67a504f4f6a51328f',
        'acf65e1d62cb58a2bafd6ffab40fb88699c47397cf5cb483d42d69cad34cd48b',
        'af207c61fd9c7cf92c2afe8154282dc3f2cbf32f75cd172814c52b03b7ebc258',
        'b1124142a5a1a5a28819c735340eff8c9e2f8168fee3ba187f253bc1a392d7e2',
        'b2def5362ad3facd04bd29047a43844f767034ea4892f80e56bee690243e2502',
        'bcfb44aab9ad021015706b4121ea761c81c9e88967590f6f94ae744dc88b78fb',
        'c07135f6b452398264a4776dbd0a6a307c60a36f967bd26321dcb817b5c0c481',
        'cab482cd3e820c5ce72aa3b6fdbe988bb8a4f0407ecafd8c926e36824eab92dd',
        'd2f91a04e3a61d4ead7848c8d43b5e1152d885727489bc65738b67c0a22785a7',
        'd3a25da80db7bab129a066ab41503dddffa02c768c0589f99fd71193e69916b6',
        'd4af6c0a482310bd7c54bb7ab121916f86c0c07cd52fcac32d3844c26005115f',
        'da800b80b2a87d399e66fa19d72fdf49983b47d8cf322c7c79503a0c7e28feaf',
        'f15f1d323ed9ca98e9ea95b33ec5dda47ea4c329f952c16f65ad419e64520476',
        'f2e9365ea121df5eebd8de2468fdc171dc0a9e46dadc1ab41d52790ba980a7c2',
        'f53c22059817dd96f400651639d2f857e21070a59abed9079400d9f695506900',
        'f6b59c8e2789a1fd5d5b253742feadc6925cb93edc345e53166e12c52ba2a601',
        'ff5680cd73a5703da04817a075fd462506a73506c4b81a1583ef549478d26476',
    ]

    _CA_KEYS_WHITELIST = [
        # kSymantecExceptions
        '56e98deac006a729afa2ed79f9e419df69f451242596d2aaf284c74a855e352e',
        '7289c06dedd16b71a7dcca66578572e2e109b11d70ad04c2601b6743bc66d07b',
        '8bb593a93be1d0e8a822bb887c547890c3e706aad2dab76254f97fb36b82fc26',
        'b5cf82d47ef9823f9aa78f123186c52e8879ea84b0f822c91d83e04279b78fd5',
        'b94c198300cec5c057ad0727b70bbe91816992256439a7b32f4598119dda9c97',
        'c0554bde87a075ec13a61f275983ae023957294b454caf0a9724e3b21b7935bc',
        'e24f8e8c2185da2f5e88d4579e817c47bf6eafbc8505f0f960fd5a0df4473ad3',
        'ec722969cb64200ab6638f68ac538e40abab5b19a6485661042a1061c4612776',
        'fae46000d8f7042558541e98acf351279589f83b6d3001c18442e4403d111849',

        # kSymantecManagedCAs
        '7cac9a0ff315387750ba8bafdb1c2bc29b3f0bba16362ca93a90f84da2df5f3e',
        'ac50b5fb738aed6cb781cc35fbfff7786f77109ada7c08867c04a573fd5cf9ee',
    ]

    @classmethod
    def get_distrust_timeline(
            cls,
            verified_certificate_chain: List[Certificate]
    ) -> Optional[SymantecDistrustTimelineEnum]:
        has_whitelisted_cert = False
        has_blacklisted_cert = False

        # Is there a Symantec root certificate in the chain?
        for certificate in verified_certificate_chain:
            key_hash = binascii.hexlify(CertificateUtils.get_public_key_sha256(certificate)).decode('ascii')
            if key_hash in cls._CA_KEYS_BLACKLIST:
                has_blacklisted_cert = True
            if key_hash in cls._CA_KEYS_WHITELIST:
                has_whitelisted_cert = True

        distrust_enum = None
        if has_blacklisted_cert and not has_whitelisted_cert:
            leaf_cert = verified_certificate_chain[0]
            if leaf_cert.not_valid_before < datetime(year=2016, month=6, day=1):
                distrust_enum = SymantecDistrustTimelineEnum.MARCH_2018
            else:
                distrust_enum = SymantecDistrustTimelineEnum.SEPTEMBER_2018
        return distrust_enum
