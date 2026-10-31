from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
from sslyze.mozilla_tls_profile.tls_config_checker import (
    ServerNotCompliantWithTlsConfiguration,
    TlsConfigurationAsJson,
    _MozillaCiphersAsJson,
    check_server_against_tls_configuration,
)


class TestCustomTlsConfigurationChecker:
    def test_custom_config_compliance_checking_noncompliant_server(self):
        # Given a custom TLS configuration
        lenient_config = TlsConfigurationAsJson(
            tls_versions={"TLSv1.2", "TLSv1.3", "TLSv1.1", "TLSv1.0"},
            certificate_types={"ecdsa", "rsa"},
            certificate_curves={"secp256r1", "secp384r1", "secp521r1"},
            certificate_signatures={
                "ecdsa-with-SHA256",
                "ecdsa-with-SHA384",
                "ecdsa-with-SHA512",
                "sha256WithRSAEncryption",
                "sha384WithRSAEncryption",
                "sha512WithRSAEncryption",
            },
            ciphersuites={"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"},
            ciphers=_MozillaCiphersAsJson(
                caddy={
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                },
                go={
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                },
                iana={
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                },
                openssl={
                    "ECDHE-ECDSA-AES256-GCM-SHA384",
                    "ECDHE-RSA-AES256-GCM-SHA384",
                    "ECDHE-ECDSA-AES128-GCM-SHA256",
                    "ECDHE-RSA-AES128-GCM-SHA256",
                },
            ),
            tls_curves={"secp256r1", "secp384r1", "x25519"},
            rsa_key_size=2048,
            dh_param_size=2048,
            ecdh_param_size=256,
            hsts_min_age=31536000,
            maximum_certificate_lifespan=365,
            recommended_certificate_lifespan=90,
            ocsp_staple=False,
            server_preferred_order=False,
        )

        # When checking a server that's not compliant with this configuration
        scanner = Scanner()
        scanner.queue_scans([ServerScanRequest(server_location=ServerNetworkLocation(hostname="www.mozilla.com"))])
        server_scan_result = next(scanner.get_results())

        # Then the compliance check runs successfully but raises an exception
        was_exception_raised = False
        try:
            check_server_against_tls_configuration(
                server_scan_result=server_scan_result, tls_config_to_check_against=lenient_config
            )
        except ServerNotCompliantWithTlsConfiguration:
            was_exception_raised = True

        assert was_exception_raised
