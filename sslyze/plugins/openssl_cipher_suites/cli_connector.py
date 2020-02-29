from typing import List, TYPE_CHECKING, ClassVar

from nassl.ssl_client import OpenSslVersionEnum

from sslyze.plugins.plugin_base import ScanCommandCliConnector

if TYPE_CHECKING:
    from sslyze.plugins.openssl_cipher_suites.scan_commands import CipherSuitesScanResult


class _CipherSuitesCliConnector(ScanCommandCliConnector["CipherSuitesScanResult", None]):

    _title_in_output: ClassVar[str]

    @classmethod
    def result_to_console_output(cls, result: "CipherSuitesScanResult") -> List[str]:
        result_as_txt = [cls._format_title(cls._title_in_output)]

        cipher_suites_count = len(result.accepted_cipher_suites) + len(result.rejected_cipher_suites)
        if not result.accepted_cipher_suites:
            result_as_txt.append(
                cls._format_subtitle(
                    f"Attempted to connect using {cipher_suites_count} cipher suites;"
                    f" the server rejected all cipher suites."
                )
            )
        else:
            # Display all ciphers that were accepted
            # TODO: DH info
            result_as_txt.append(
                cls._format_subtitle(f"Attempted to connect using {cipher_suites_count} cipher suites.")
            )
            result_as_txt.append("")
            result_as_txt.append(
                cls._format_subtitle(
                    f"The server accepted the following {len(result.accepted_cipher_suites)} cipher suites:"
                )
            )
            for accepted_cipher in result.accepted_cipher_suites:
                result_as_txt.append(
                    f"        {accepted_cipher.cipher_suite.name:<50}{accepted_cipher.cipher_suite.key_size:<10}"
                )
            result_as_txt.append("")

            # Display some general comments about the cipher suite configuration
            result_as_txt.append(
                cls._format_subtitle(
                    f"The group of cipher suites supported by the server has the following properties:"
                )
            )

            # Forward secrecy
            supports_forward_secrecy = False
            if result.tls_version_used == OpenSslVersionEnum.TLSV1_3:
                # All TLS 1.3 cipher suites support forward secrecy
                supports_forward_secrecy = True
            else:
                for accepted_cipher in result.accepted_cipher_suites:
                    if "_DHE_" in accepted_cipher.cipher_suite.name or "_ECDHE_" in accepted_cipher.cipher_suite.name:
                        supports_forward_secrecy = True
                        break

            result_as_txt.append(
                cls._format_field(
                    "Forward Secrecy", "OK - Supported" if supports_forward_secrecy else "INSECURE - Not Supported"
                )
            )

            # Insecure RC4 cipher suites
            supports_rc4 = False
            for accepted_cipher in result.accepted_cipher_suites:
                if "_RC4_" in accepted_cipher.cipher_suite.name:
                    supports_rc4 = True
                    break
            result_as_txt.append(
                cls._format_field(
                    "Legacy RC4 Algorithm", "INSECURE - Supported" if supports_rc4 else "OK - Not Supported"
                )
            )
            result_as_txt.append("")

            # Then display the preferred cipher
            if result.cipher_suite_preferred_by_server:
                result_as_txt.append(
                    cls._format_subtitle("The server is configured to prefer the following cipher suite:")
                )
                result_as_txt.append(
                    f"        {result.cipher_suite_preferred_by_server.cipher_suite.name:<50}"
                    f"{result.cipher_suite_preferred_by_server.cipher_suite.key_size:<10}"
                )
            else:
                result_as_txt.append(
                    cls._format_subtitle(
                        "The server has no preferred cipher suite and will follow the client's preference."
                    )
                )
            result_as_txt.append("")

        return result_as_txt
