# TODO: Fix me
# list from https://tools.ietf.org/html/rfc4492#section-5.1.1 and https://tools.ietf.org/html/rfc8446#section-4.2.7
CURVE_NAMES = ["X25519", "X448", "sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2", "sect233k1",
               "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1",
               "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "prime192v1", "secp224k1",
               "secp224r1", "secp256k1", "prime256v1", "secp384r1", "secp521r1"]


def _scan_supported_ecdh_curves(self, server_connectivity_info: ServerConnectivityInfo,
                                scan_command: PluginScanCommand) -> List[str]:
    """
    Check which elliptic curves the server supports for ECDH key exchange.

    Args:
        server_connectivity_info:
        scan_command:

    Returns: List of strings (each specifying an elliptic curve)

    """
    ssl_version = self.SSL_VERSIONS_MAPPING[scan_command.__class__]

    # Don't scan for elliptic curves for SSLv2 and SSLv3 because they do not support elliptic curves key exchange
    # Source: https://tools.ietf.org/html/rfc6101#appendix-A.6
    if ssl_version == OpenSslVersionEnum.SSLV2 or ssl_version == OpenSslVersionEnum.SSLV3:
        return []

    supported_curves = []
    for curve in self.CURVE_NAMES:
        ssl_connection = server_connectivity_info.get_preconfigured_ssl_connection(override_ssl_version=ssl_version,
                                                                                   should_use_legacy_openssl=False)

        if ssl_version == OpenSslVersionEnum.TLSV1_3:
            # TLSv1.3
            ssl_connection.ssl_client.set_cipher_list("")
            # cipher suites source: https://tools.ietf.org/html/rfc8446#appendix-B.4
            ssl_connection.ssl_client.set_ciphersuites(
                "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                "TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256")
        else:
            # TLSv1.2 and older
            # cipher suite source: https://www.openssl.org/docs/man1.0.2/man1/ciphers.html
            ssl_connection.ssl_client.set_cipher_list("ECDH")

        # set curve to test whether it is supported by the server
        ssl_connection.ssl_client.set1_groups_list(curve)

        try:
            ssl_connection.connect()
            # if no error occurred check if the curve was really used
            dh_info = ssl_connection.ssl_client.get_dh_info()
            if isinstance(dh_info, EcDhKeyExchangeInfo) and dh_info.curve_name == curve.lower():
                supported_curves.append(curve)
        except SslHandshakeRejected:
            pass
        except Exception:
            break
        finally:
            ssl_connection.close()

    return supported_curves

