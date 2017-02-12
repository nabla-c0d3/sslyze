# -*- coding: utf-8 -*-

import optparse
import os
from xml.etree.ElementTree import Element

from nassl._nassl import OpenSSLError

from nassl.ocsp_response import OcspResponse, OcspResponseNotTrustedError
from nassl.ssl_client import ClientCertificateRequested
from nassl.x509_certificate import X509Certificate, HostnameValidationResultEnum
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanResult, PluginScanCommand
from sslyze.plugins.utils.certificate import Certificate
from sslyze.plugins.utils.trust_store.trust_store import TrustStore, \
    InvalidCertificateChainOrderError, AnchorCertificateNotInTrustStoreError
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

    def __init__(self, ca_file=None, print_full_certificate=False):
        # type: (Optional[Text], Optional[bool]) -> None
        """

        Args:
            ca_file (Text): The path to a custom trust store file to use for certificate validation. The file should
                contain PEM-formatted root certificates.
            print_full_certificate (bool): Deprecated - do not use.
        """
        super(CertificateInfoScanCommand, self).__init__()
        self.custom_ca_file = ca_file
        self.should_print_full_certificate = print_full_certificate

    @classmethod
    def get_cli_argument(cls):
        return u'certinfo'


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
                u'--ca_file',
                help=u'Path to a local trust store file (with root certificates in PEM format) to verify the validity '
                     u'of the server(s) certificate\'s chain(s) against.',
                dest=u'ca_file'
            )
        )
        # TODO(ad): Move this to the command line parser ?
        options.append(
            optparse.make_option(
                u'--print_full_certificate',
                help=u'Option - Print the full content of server certificate instead of selected fields.',
                action=u'store_true'
            )
        )
        return options


    def process_task(self, server_info, scan_command):
        # type: (ServerConnectivityInfo, CertificateInfoScanCommand) -> CertificateInfoScanResult
        final_trust_store_list = list(TrustStoresRepository.get_all())
        if scan_command.custom_ca_file:
            if not os.path.isfile(scan_command.custom_ca_file):
                raise ValueError(u'Could not open supplied CA file at "{}"'.format(scan_command.custom_ca_file))
            final_trust_store_list.append(TrustStore(scan_command.custom_ca_file, u'Custom --ca_file', u'N/A'))

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
            raise RuntimeError(u'Could not connect to the server; last error: {}'.format(last_exception))

        # All done
        return CertificateInfoScanResult(server_info, scan_command, certificate_chain, path_validation_result_list,
                                         path_validation_error_list, ocsp_response)


    @staticmethod
    def _get_and_verify_certificate_chain(server_info, trust_store):
        # type: (ServerConnectivityInfo, TrustStore) -> Tuple[List[X509Certificate], Text, Optional[OcspResponse]]
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


class CertificateInfoScanResult(PluginScanResult):
    """The result of running a CertificateInfoScanCommand on a specific server.

    Attributes:
        certificate_chain (List[Certificate]): The certificate chain sent by the server; index 0 is the leaf
            certificate.
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
        verified_certificate_chain (List[Certificate]): The verified certificate chain built using the
            successful_trust_store; index 0 is the leaf certificate and the last element is the anchor/CA certificate
            from the trust store. Will be empty if the validation failed with all available trust store, or the
            verified chain could not be built.
        hostname_validation_result (HostnameValidationResultEnum): Validation result of the certificate hostname.
        is_leaf_certificate_ev (bool): True if the leaf certificate is Extended Validation according to Mozilla.
        ocsp_response (Optional[Dict]): The OCSP response returned by the server. None if no response was sent by the
            server.
        is_ocsp_response_trusted (Optional[bool]): True if the OCSP response is trusted using the Mozilla trust store.
            None if no OCSP response was sent by the server.
        has_sha1_in_certificate_chain (bool): True if any of the leaf or intermediate certificates are signed using the
            SHA-1 algorithm. None if the verified chain could not be built or no HPKP header was returned.
        has_anchor_in_certificate_chain (bool): True if the server included the anchor/root certificate in the chain it
            send back to clients. None if the verified chain could not be built or no HPKP header was returned.
    """

    COMMAND_TITLE = u'Certificate Basic Information'

    def __init__(
            self,
            server_info,                    # type: ServerConnectivityInfo
            scan_command,                   # type: CertificateInfoScanCommand
            certificate_chain,              # type: List[X509Certificate]
            path_validation_result_list,    # type: List[PathValidationResult]
            path_validation_error_list,     # type: List[PathValidationError]
            ocsp_response                   # type: OcspResponse
            ):
        # type: (...) -> None
        super(CertificateInfoScanResult, self).__init__(server_info, scan_command)
        # Find the first trust store that successfully validated the certificate chain
        self.successful_trust_store = None
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

        # We create pickable Certificates from nassl.X509Certificates which are not pickable
        self.certificate_chain = [Certificate.from_nassl(x509_cert) for x509_cert in certificate_chain]

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
        self.hostname_validation_result = certificate_chain[0].matches_hostname(server_info.tls_server_name_indication)

        # Check if a SHA1-signed certificate is in the chain
        # Root certificates can still be signed with SHA1 so we only check leaf and intermediate certificates
        self.has_sha1_in_certificate_chain = None
        if self.verified_certificate_chain:
            self.has_sha1_in_certificate_chain = False
            for cert in self.verified_certificate_chain[:-1]:
                if u"sha1" in cert.as_dict['signatureAlgorithm']:
                    self.has_sha1_in_certificate_chain = True
                    break


    HOST_VALIDATION_TEXT = {
        HostnameValidationResultEnum.NAME_MATCHES_SAN: u'OK - Subject Alternative Name matches {hostname}',
        HostnameValidationResultEnum.NAME_MATCHES_CN: u'OK - Common Name matches {hostname}',
        HostnameValidationResultEnum.NAME_DOES_NOT_MATCH: u'FAILED - Certificate does NOT match {hostname}'
    }

    TRUST_FORMAT = u'{store_name} CA Store ({store_version}):'

    NO_VERIFIED_CHAIN_ERROR_TXT = u'ERROR - Could not build verified chain (certificate untrusted?)'

    def as_text(self):
        text_output = [self._format_title(self.COMMAND_TITLE)]
        if self.scan_command.should_print_full_certificate:
            text_output.extend(self._get_full_certificate_text())
        else:
            text_output.extend(self._get_basic_certificate_text())

        # Trust section
        text_output.extend(['', self._format_title(u'Certificate - Trust')])

        # Hostname validation
        server_name_indication = self.server_info.tls_server_name_indication
        if self.server_info.tls_server_name_indication != self.server_info.hostname:
            text_output.append(self._format_field(u"SNI enabled with virtual domain:", server_name_indication))

        text_output.append(self._format_field(
            u"Hostname Validation:",
            self.HOST_VALIDATION_TEXT[self.hostname_validation_result].format(hostname=server_name_indication)
        ))

        # Path validation that was successfully tested
        for path_result in self.path_validation_result_list:
            if path_result.is_certificate_trusted:
                # EV certs - Only Mozilla supported for now
                ev_txt = u''
                if self.is_leaf_certificate_ev and TrustStoresRepository.get_main() == path_result.trust_store:
                    ev_txt = u', Extended Validation'
                path_txt = u'OK - Certificate is trusted{}'.format(ev_txt)

            else:
                path_txt = u'FAILED - Certificate is NOT Trusted: {}'.format(path_result.verify_string)

            text_output.append(self._format_field(
                self.TRUST_FORMAT.format(store_name=path_result.trust_store.name,
                                         store_version=path_result.trust_store.version),
                path_txt))

        # Path validation that ran into errors
        for path_error in self.path_validation_error_list:
            error_txt = u'ERROR: {}'.format(path_error.error_message)
            text_output.append(self._format_field(
                self.TRUST_FORMAT.format(store_name=path_result.trust_store.name,
                                         store_version=path_result.trust_store.version),
                error_txt))

        # Print the Common Names within the certificate chain
        cns_in_certificate_chain = [cert.printable_subject_name for cert in self.certificate_chain]
        text_output.append(self._format_field(u'Received Chain:', u' --> '.join(cns_in_certificate_chain)))

        # Print the Common Names within the verified certificate chain if validation was successful
        if self.verified_certificate_chain:
            cns_in_certificate_chain = [cert.printable_subject_name for cert in self.verified_certificate_chain]
            verified_chain_txt = u' --> '.join(cns_in_certificate_chain)
        else:
            verified_chain_txt = self.NO_VERIFIED_CHAIN_ERROR_TXT
        text_output.append(self._format_field(u'Verified Chain:', verified_chain_txt))

        if self.verified_certificate_chain:
            chain_with_anchor_txt = u'OK - Anchor certificate not sent' if not self.has_anchor_in_certificate_chain \
                else u'WARNING - Received certificate chain contains the anchor certificate'
        else:
            chain_with_anchor_txt = self.NO_VERIFIED_CHAIN_ERROR_TXT
        text_output.append(self._format_field(u'Received Chain Contains Anchor:', chain_with_anchor_txt))

        chain_order_txt = u'OK - Order is valid' if self.is_certificate_chain_order_valid \
            else u'FAILED - Certificate chain out of order!'
        text_output.append(self._format_field(u'Received Chain Order:', chain_order_txt))

        if self.verified_certificate_chain:
            sha1_text = u'OK - No SHA1-signed certificate in the verified certificate chain' \
                if not self.has_sha1_in_certificate_chain \
                else u'INSECURE - SHA1-signed certificate in the verified certificate chain'
        else:
            sha1_text = self.NO_VERIFIED_CHAIN_ERROR_TXT

        text_output.append(self._format_field(u'Verified Chain contains SHA1:', sha1_text))

        # OCSP stapling
        text_output.extend(['', self._format_title(u'Certificate - OCSP Stapling')])

        if self.ocsp_response is None:
            text_output.append(self._format_field(u'', u'NOT SUPPORTED - Server did not send back an OCSP response.'))

        else:
            try:
                ocsp_trust_txt = u'OK - Response is trusted' \
                    if self.is_ocsp_response_trusted \
                    else u'FAILED - Response is NOT trusted'
            except OpenSSLError as e:
                if u'certificate verify error' in str(e):
                    ocsp_trust_txt = u'FAILED - Response is NOT trusted'
                else:
                    raise

            ocsp_resp_txt = [
                self._format_field(u'OCSP Response Status:', self.ocsp_response[u'responseStatus']),
                self._format_field(u'Validation w/ Mozilla Store:', ocsp_trust_txt),
                self._format_field(u'Responder Id:', self.ocsp_response[u'responderID'])]

            if u'successful' in self.ocsp_response[u'responseStatus']:
                ocsp_resp_txt.extend([
                    self._format_field(u'Cert Status:', self.ocsp_response['responses'][0]['certStatus']),
                    self._format_field(u'Cert Serial Number:',
                                       self.ocsp_response['responses'][0]['certID']['serialNumber']),
                    self._format_field(u'This Update:', self.ocsp_response['responses'][0]['thisUpdate']),
                    self._format_field(u'Next Update:', self.ocsp_response['responses'][0]['nextUpdate'])
                ])
            text_output.extend(ocsp_resp_txt)

        # All done
        return text_output


    def as_xml(self):
        xml_output = Element(self.scan_command.get_cli_argument(), title=self.COMMAND_TITLE)

        # Certificate chain
        cert_xml_list = []
        for index, certificate in enumerate(self.certificate_chain, start=0):
            cert_xml = Element('certificate', attrib={
                'sha1Fingerprint': certificate.sha1_fingerprint,
                'position': 'leaf' if index == 0 else 'intermediate',
                'suppliedServerNameIndication': self.server_info.tls_server_name_indication,
                'hpkpSha256Pin': certificate.hpkp_pin
            })

            # Add the PEM cert
            cert_as_pem_xml = Element('asPEM')
            cert_as_pem_xml.text = certificate.as_pem
            cert_xml.append(cert_as_pem_xml)

            # Add the parsed certificate
            for key, value in certificate.as_dict.items():
                cert_xml.append(_keyvalue_pair_to_xml(key, value))
            cert_xml_list.append(cert_xml)


        cert_chain_attrs = {'isChainOrderValid': str(self.is_certificate_chain_order_valid)}
        if self.verified_certificate_chain:
            cert_chain_attrs['containsAnchorCertificate'] = str(False) if not self.has_anchor_in_certificate_chain \
                else str(True)
        cert_chain_xml = Element('receivedCertificateChain', attrib=cert_chain_attrs)

        for cert_xml in cert_xml_list:
            cert_chain_xml.append(cert_xml)
        xml_output.append(cert_chain_xml)


        # Trust
        trust_validation_xml = Element('certificateValidation')

        # Hostname validation
        is_hostname_valid = 'False' \
            if self.hostname_validation_result == HostnameValidationResultEnum.NAME_DOES_NOT_MATCH \
            else 'True'
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

            # Things we only do with the Mozilla store
            verified_cert_chain_xml = None
            if 'Mozilla' in path_result.trust_store.name:
                # EV certs
                if self.is_leaf_certificate_ev:
                    path_attrib_xml['isExtendedValidationCertificate'] = str(self.is_leaf_certificate_ev)

                # Verified chain
                if self.verified_certificate_chain:
                    verified_cert_chain_xml = Element(
                        'verifiedCertificateChain',
                        {'hasSha1SignedCertificate': str(self.has_sha1_in_certificate_chain)}
                    )
                    for certificate in self.certificate_chain:
                        cert_xml = Element('certificate', attrib={
                            'sha1Fingerprint': certificate.sha1_fingerprint,
                            'suppliedServerNameIndication': self.server_info.tls_server_name_indication,
                            'hpkpSha256Pin': certificate.hpkp_pin
                        })

                        # Add the PEM cert
                        cert_as_pem_xml = Element('asPEM')
                        cert_as_pem_xml.text = certificate.as_pem
                        cert_xml.append(cert_as_pem_xml)

                        # Add the parsed certificate
                        for key, value in certificate.as_dict.items():
                            cert_xml.append(_keyvalue_pair_to_xml(key, value))
                        cert_xml_list.append(cert_xml)

                        verified_cert_chain_xml.append(cert_xml)

            path_valid_xml = Element('pathValidation', attrib=path_attrib_xml)
            if verified_cert_chain_xml is not None:
                path_valid_xml.append(verified_cert_chain_xml)

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


    def _get_full_certificate_text(self):
        return [self.certificate_chain[0].as_text]


    def _get_basic_certificate_text(self):
        cert_dict = self.certificate_chain[0].as_dict

        text_output = [
            self._format_field(u"SHA1 Fingerprint:", self.certificate_chain[0].sha1_fingerprint),
            self._format_field(u"Common Name:", self.certificate_chain[0].printable_subject_name),
            self._format_field(u"Issuer:", self.certificate_chain[0].printable_issuer_name),
            self._format_field(u"Serial Number:", cert_dict[u'serialNumber']),
            self._format_field(u"Not Before:", cert_dict[u'validity'][u'notBefore']),
            self._format_field(u"Not After:", cert_dict[u'validity'][u'notAfter']),
            self._format_field(u"Signature Algorithm:", cert_dict[u'signatureAlgorithm']),
            self._format_field(u"Public Key Algorithm:", cert_dict[u'subjectPublicKeyInfo'][u'publicKeyAlgorithm']),
            self._format_field(u"Key Size:", cert_dict[u'subjectPublicKeyInfo'][u'publicKeySize'])]

        try:
            # Print the Public key exponent if there's one; EC public keys don't have one for example
            text_output.append(self._format_field(u"Exponent:", u"{0} (0x{0:x})".format(
                int(cert_dict[u'subjectPublicKeyInfo'][u'publicKey'][u'exponent']))))
        except KeyError:
            pass

        try:
            # Print the SAN extension if there's one
            text_output.append(self._format_field(u'X509v3 Subject Alternative Name:',
                                                  cert_dict[u'extensions'][u'X509v3 Subject Alternative Name']))
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

    if type(value) in [str, unicode]:  # value is a string
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

