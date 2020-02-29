import binascii
from pathlib import Path
from typing import List, Union, Dict, Optional, Tuple, TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from nassl.ocsp_response import OcspResponseStatusEnum

from sslyze.plugins.certificate_info.symantec import SymantecDistrustTimelineEnum
from sslyze.plugins.plugin_base import ScanCommandCliConnector, OptParseCliOption, ScanCommandExtraArguments
from sslyze.plugins.certificate_info.certificate_utils import CertificateUtils

if TYPE_CHECKING:
    from sslyze.plugins.certificate_info.core import CertificateInfoScanResult


class _CertificateInfoCliConnector(ScanCommandCliConnector):

    _cli_option = "certinfo"
    _cli_description = "Retrieve and analyze a server's certificate(s) to verify its validity."

    @classmethod
    def get_cli_options(cls) -> List[OptParseCliOption]:
        scan_command_option = super().get_cli_options()
        scan_command_option.append(
            OptParseCliOption(
                option="certinfo_ca_file",
                help="Path to a file containing root certificates in PEM format that will be used to verify the"
                " validity of the server's certificate.",
                action="store",
            )
        )
        return scan_command_option

    @classmethod
    def find_cli_options_in_command_line(
        cls, parsed_command_line: Dict[str, Union[None, bool, str]]
    ) -> Tuple[bool, Optional[ScanCommandExtraArguments]]:
        from sslyze.plugins.certificate_info.core import CertificateInfoExtraArguments  # Avoid circular imports

        # Check if --certinfo was used
        is_scan_cmd_enabled, _ = super().find_cli_options_in_command_line(parsed_command_line)

        # Check if --certinfo_ca_file was used
        extra_arguments = None
        try:
            certinfo_ca_file = parsed_command_line["certinfo_ca_file"]
            if certinfo_ca_file:
                extra_arguments = CertificateInfoExtraArguments(custom_ca_file=Path(certinfo_ca_file))
        except KeyError:
            pass

        return is_scan_cmd_enabled, extra_arguments

    TRUST_FORMAT = "{store_name} CA Store ({store_version}):"
    NO_VERIFIED_CHAIN_ERROR_TXT = "ERROR - Could not build verified chain (certificate untrusted?)"

    @classmethod
    def result_to_console_output(cls, result: "CertificateInfoScanResult") -> List[str]:
        result_as_txt = [cls._format_title("Certificate Information")]

        result_as_txt.extend(cls._get_basic_certificate_text(result))

        # Trust section
        result_as_txt.append("")
        result_as_txt.append(cls._format_subtitle("Trust"))

        # Hostname validation
        server_name_indication = result.hostname_used_for_server_name_indication
        result_as_txt.append(cls._format_field("Hostname used for SNI:", server_name_indication))

        hostname_validation_text = (
            "OK - Certificate matches {hostname}".format(hostname=server_name_indication)
            if result.leaf_certificate_subject_matches_hostname
            else "FAILED - Certificate does NOT match {hostname}".format(hostname=server_name_indication)
        )
        result_as_txt.append(cls._format_field("Hostname Validation:", hostname_validation_text))

        # Path validation that was successfully tested
        for path_result in result.path_validation_results:
            if path_result.was_validation_successful:
                # EV certs - Only Mozilla supported for now
                ev_txt = ""
                if result.leaf_certificate_is_ev and path_result.trust_store.ev_oids:
                    ev_txt = ", Extended Validation"
                path_txt = "OK - Certificate is trusted{}".format(ev_txt)

            else:
                path_txt = "FAILED - Certificate is NOT Trusted: {}".format(path_result.openssL_verify_string)

            result_as_txt.append(
                cls._format_field(
                    cls.TRUST_FORMAT.format(
                        store_name=path_result.trust_store.name, store_version=path_result.trust_store.version
                    ),
                    path_txt,
                )
            )

        if result.verified_chain_has_legacy_symantec_anchor:
            timeline_str = (
                "March 2018"
                if result.verified_chain_has_legacy_symantec_anchor == SymantecDistrustTimelineEnum.MARCH_2018
                else "September 2018"
            )
            symantec_str = "WARNING: Certificate distrusted by Google and Mozilla on {}".format(timeline_str)
        else:
            symantec_str = "OK - Not a Symantec-issued certificate"
        result_as_txt.append(cls._format_field("Symantec 2018 Deprecation:", symantec_str))

        # Print the Common Names within the certificate chain
        cns_in_certificate_chain = [
            CertificateUtils.get_name_as_short_text(cert.subject) for cert in result.received_certificate_chain
        ]
        result_as_txt.append(cls._format_field("Received Chain:", " --> ".join(cns_in_certificate_chain)))

        # Print the Common Names within the verified certificate chain if validation was successful
        if result.verified_certificate_chain:
            cns_in_certificate_chain = [
                CertificateUtils.get_name_as_short_text(cert.subject) for cert in result.verified_certificate_chain
            ]
            verified_chain_txt = " --> ".join(cns_in_certificate_chain)
        else:
            verified_chain_txt = cls.NO_VERIFIED_CHAIN_ERROR_TXT
        result_as_txt.append(cls._format_field("Verified Chain:", verified_chain_txt))

        if result.verified_certificate_chain:
            chain_with_anchor_txt = (
                "OK - Anchor certificate not sent"
                if not result.received_chain_contains_anchor_certificate
                else "WARNING - Received certificate chain contains the anchor certificate"
            )
        else:
            chain_with_anchor_txt = cls.NO_VERIFIED_CHAIN_ERROR_TXT
        result_as_txt.append(cls._format_field("Received Chain Contains Anchor:", chain_with_anchor_txt))

        chain_order_txt = (
            "OK - Order is valid"
            if result.received_chain_has_valid_order
            else "FAILED - Certificate chain out of order!"
        )
        result_as_txt.append(cls._format_field("Received Chain Order:", chain_order_txt))

        if result.verified_certificate_chain:
            sha1_text = (
                "OK - No SHA1-signed certificate in the verified certificate chain"
                if not result.verified_chain_has_sha1_signature
                else "INSECURE - SHA1-signed certificate in the verified certificate chain"
            )
        else:
            sha1_text = cls.NO_VERIFIED_CHAIN_ERROR_TXT
        result_as_txt.append(cls._format_field("Verified Chain contains SHA1:", sha1_text))

        # Extensions section
        result_as_txt.extend(["", cls._format_subtitle("Extensions")])

        # OCSP must-staple
        must_staple_txt = (
            "OK - Extension present"
            if result.leaf_certificate_has_must_staple_extension
            else "NOT SUPPORTED - Extension not found"
        )
        result_as_txt.append(cls._format_field("OCSP Must-Staple:", must_staple_txt))

        # Look for SCT extension
        scts_count = result.leaf_certificate_signed_certificate_timestamps_count
        if scts_count is None:
            sct_txt = "OK - Extension present"
        elif scts_count == 0:
            sct_txt = "NOT SUPPORTED - Extension not found"
        elif scts_count < 3:
            sct_txt = "WARNING - Only {} SCTs included but Google recommends 3 or more".format(str(scts_count))
        else:
            sct_txt = "OK - {} SCTs included".format(str(scts_count))
        result_as_txt.append(cls._format_field("Certificate Transparency:", sct_txt))

        # OCSP stapling
        result_as_txt.extend(["", cls._format_subtitle("OCSP Stapling")])

        if result.ocsp_response is None:
            result_as_txt.append(cls._format_field("", "NOT SUPPORTED - Server did not send back an OCSP response"))

        else:
            if result.ocsp_response_status != OcspResponseStatusEnum.SUCCESSFUL:
                ocsp_resp_txt = [
                    cls._format_field(
                        "",
                        "ERROR - OCSP response status is not successful: {}".format(result.ocsp_response_status.name),
                    )
                ]
            else:
                ocsp_trust_txt = (
                    "OK - Response is trusted"
                    if result.ocsp_response_is_trusted
                    else "FAILED - Response is NOT trusted"
                )

                ocsp_resp_txt = [
                    cls._format_field("OCSP Response Status:", result.ocsp_response["responseStatus"]),
                    cls._format_field("Validation w/ Mozilla Store:", ocsp_trust_txt),
                    cls._format_field("Responder Id:", result.ocsp_response["responderID"]),
                ]

                if "successful" in result.ocsp_response["responseStatus"]:
                    ocsp_resp_txt.extend(
                        [
                            cls._format_field("Cert Status:", result.ocsp_response["responses"][0]["certStatus"]),
                            cls._format_field(
                                "Cert Serial Number:", result.ocsp_response["responses"][0]["certID"]["serialNumber"]
                            ),
                            cls._format_field("This Update:", result.ocsp_response["responses"][0]["thisUpdate"]),
                            cls._format_field("Next Update:", result.ocsp_response["responses"][0]["nextUpdate"]),
                        ]
                    )
            result_as_txt.extend(ocsp_resp_txt)

        # All done
        return result_as_txt

    @classmethod
    def _get_basic_certificate_text(cls, result) -> List[str]:
        certificate = result.received_certificate_chain[0]
        public_key = result.received_certificate_chain[0].public_key()
        text_output = [
            cls._format_field(
                "SHA1 Fingerprint:", binascii.hexlify(certificate.fingerprint(hashes.SHA1())).decode("ascii")
            ),
            cls._format_field("Common Name:", CertificateUtils.get_name_as_short_text(certificate.subject)),
            cls._format_field("Issuer:", CertificateUtils.get_name_as_short_text(certificate.issuer)),
            cls._format_field("Serial Number:", certificate.serial_number),
            cls._format_field("Not Before:", certificate.not_valid_before),
            cls._format_field("Not After:", certificate.not_valid_after),
            cls._format_field("Signature Algorithm:", certificate.signature_hash_algorithm.name),
            cls._format_field("Public Key Algorithm:", CertificateUtils.get_public_key_type(certificate)),
        ]

        if isinstance(public_key, EllipticCurvePublicKey):
            text_output.append(cls._format_field("Key Size:", public_key.curve.key_size))
            text_output.append(cls._format_field("Curve:", public_key.curve.name))
        elif isinstance(public_key, RSAPublicKey):
            text_output.append(cls._format_field("Key Size:", public_key.key_size))
            text_output.append(cls._format_field("Exponent:", "{0} (0x{0:x})".format(public_key.public_numbers().e)))
        else:
            # DSA Key? https://github.com/nabla-c0d3/sslyze/issues/314
            pass

        try:
            # Print the SAN extension if there's one
            text_output.append(
                cls._format_field(
                    "DNS Subject Alternative Names:",
                    str(CertificateUtils.get_dns_subject_alternative_names(certificate)),
                )
            )
        except KeyError:
            pass

        return text_output
