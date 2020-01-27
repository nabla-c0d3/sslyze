from sslyze.plugins.openssl_cipher_suites.scan_commands import Sslv20ScanImplementation, CipherSuitesScanResult, \
    Sslv30ScanImplementation, Tlsv10ScanImplementation, Tlsv11ScanImplementation, Tlsv12ScanImplementation
from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection
from tests.markers import can_only_run_on_linux_64
from tests.openssl_server import LegacyOpenSslServer, ModernOpenSslServer, ClientAuthConfigEnum


class TestCipherSuitesPluginWithOnlineServer:

    def test_sslv2_disabled(self):
        # Given a server to scan that does not support SSL 2.0
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "www.google.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Sslv20ScanImplementation.perform(server_info)

        # And the result confirms that SSL 2.0 is not supported
        assert result.preferred_cipher_suite is None
        assert not result.accepted_cipher_suites
        assert result.rejected_cipher_suites

    def test_sslv3_disabled(self):
        # Given a server to scan that does not support SSL 3.0
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "www.google.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Sslv30ScanImplementation.perform(server_info)

        # And the result confirms that SSL 3.0 is not supported
        assert result.preferred_cipher_suite is None
        assert not result.accepted_cipher_suites
        assert result.rejected_cipher_suites

    def test_tlsv1_0_enabled(self):
        # Given a server to scan that supports TLS 1.0
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "www.google.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv10ScanImplementation.perform(server_info)

        # And the result confirms that TLS 1.0 is supported
        assert result.preferred_cipher_suite
        expected_ciphers = {
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        }
        assert expected_ciphers == {cipher.name for cipher in result.accepted_cipher_suites}

        assert result.rejected_cipher_suites

    def test_tlsv1_0_disabled(self):
        # Given a server to scan that does NOT support TLS 1.0
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "success.trendmicro.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv10ScanImplementation.perform(server_info)

        # And the result confirms that TLS 1.0 is not supported
        assert result.preferred_cipher_suite is None
        assert not result.accepted_cipher_suites
        assert result.rejected_cipher_suites

    def test_tlsv1_1_enabled(self):
        # Given a server to scan that supports TLS 1.1
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "www.google.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv11ScanImplementation.perform(server_info)

        # And the result confirms that TLS 1.1 is not supported
        assert result.preferred_cipher_suite
        expected_ciphers = {
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        }
        assert expected_ciphers == {cipher.name for cipher in result.accepted_cipher_suites}

        assert result.rejected_cipher_suites

    def test_tlsv1_2_enabled(self):
        # Given a server to scan that supports TLS 1.2
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "www.google.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.perform(server_info)

        # And the result confirms that TLS 1.2 is not supported
        assert result.preferred_cipher_suite
        expected_ciphers = {
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_256_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
        }
        assert expected_ciphers == {cipher.name for cipher in result.accepted_cipher_suites}

    def test_null_cipher_suites(self):
        # Given a server to scan that supports NULL cipher suites
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "null.badssl.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.perform(server_info)

        # And the NULL/Anon cipher suites were detected
        expected_ciphers = {
            'TLS_ECDH_anon_WITH_AES_256_CBC_SHA', 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
            'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA', 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
            'TLS_DH_anon_WITH_AES_256_CBC_SHA', 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
            'TLS_DH_anon_WITH_AES_128_CBC_SHA256', 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
            'TLS_DH_anon_WITH_AES_128_GCM_SHA256', 'TLS_DH_anon_WITH_SEED_CBC_SHA',
            'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_NULL_SHA',
            'TLS_ECDH_anon_WITH_NULL_SHA', 'TLS_RSA_WITH_NULL_SHA256', 'TLS_RSA_WITH_NULL_SHA'
        }
        assert expected_ciphers == {cipher.name for cipher in result.accepted_cipher_suites}

    def test_rc4_cipher_suites(self):
        # Given a server to scan that supports RC4 cipher suites
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "rc4.badssl.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.perform(server_info)

        # And the RC4 cipher suites were detected
        assert {'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_RC4_128_SHA'} == {
            cipher.name for cipher in result.accepted_cipher_suites
        }

    def test_does_not_follow_client_cipher_suite_preference(self):
        # Given a server to scan that does not follow client cipher suite preference
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "www.google.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.perform(server_info)

        # And the server is detected as not following the client's preference
        assert not result.follows_cipher_suite_preference_from_client

    def test_follows_client_cipher_suite_preference(self):
        # Given a server to scan that follows client cipher suite preference
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            "www.sogou.com", 443
        )
        server_info = ServerConnectivityTester().perform(server_location)

        # When scanning for cipher suites, it succeeds
        result: CipherSuitesScanResult = Tlsv12ScanImplementation.perform(server_info)

        # And the server is detected as following the client's preference
        assert result.follows_cipher_suite_preference_from_client

    def test_smtp_post_handshake_response(self):
        server_test = ServerConnectivityTester(
            hostname='smtp.gmail.com',
            port=587,
            tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP
        )
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

    def test_tls_1_3_cipher_suites(self):
        server_test = ServerConnectivityTester(hostname='www.cloudflare.com')
        server_info = server_test.perform()

        plugin = OpenSslCipherSuitesPlugin()
        plugin_result = plugin.process_task(server_info, Tlsv13ScanCommand())

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        assert {'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256'} == \
            set(accepted_cipher_name_list)


@can_only_run_on_linux_64
class TestCipherSuitesPluginWithLocalServer:

    def test_sslv2_enabled(self):
        with LegacyOpenSslServer() as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            plugin = OpenSslCipherSuitesPlugin()
            plugin_result = plugin.process_task(server_info, Sslv20ScanCommand())

        # The embedded server does not have a preference
        assert not plugin_result.preferred_cipher

        accepted_cipher_name_list = [cipher.name for cipher in plugin_result.accepted_cipher_list]
        assert {
                   'SSL_CK_RC4_128_EXPORT40_WITH_MD5', 'SSL_CK_IDEA_128_CBC_WITH_MD5',
                   'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5', 'SSL_CK_DES_192_EDE3_CBC_WITH_MD5',
                   'SSL_CK_DES_192_EDE3_CBC_WITH_MD5', 'SSL_CK_RC4_128_WITH_MD5',
                   'SSL_CK_RC2_128_CBC_WITH_MD5', 'SSL_CK_DES_64_CBC_WITH_MD5'
               } == set(accepted_cipher_name_list)

        assert plugin_result.accepted_cipher_list
        assert not plugin_result.rejected_cipher_list
        assert not plugin_result.errored_cipher_list

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    def test_sslv3_enabled(self):
        with LegacyOpenSslServer() as server:
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port)
            server_info = server_test.perform()

            plugin = OpenSslCipherSuitesPlugin()
            plugin_result = plugin.process_task(server_info, Sslv30ScanCommand())

        # The embedded server does not have a preference
        assert not plugin_result.preferred_cipher
        expected_ciphers = {
            'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
            'TLS_DH_anon_WITH_AES_128_CBC_SHA', 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
            'TLS_DH_anon_WITH_SEED_CBC_SHA', 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
            'TLS_ECDHE_RSA_WITH_NULL_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
            'TLS_DH_anon_WITH_AES_256_CBC_SHA',
            'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA', 'TLS_ECDH_anon_WITH_RC4_128_SHA',
            'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
            'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5', 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
            'TLS_ECDH_anon_WITH_NULL_SHA',
            'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA',
            'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
            'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_NULL_MD5',
            'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA', 'TLS_DH_anon_WITH_DES_CBC_SHA',
            'TLS_RSA_WITH_SEED_CBC_SHA', 'TLS_RSA_WITH_DES_CBC_SHA',
            'TLS_ECDH_anon_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
            'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
            'TLS_RSA_WITH_RC4_128_MD5', 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
            'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_NULL_SHA',
            'TLS_RSA_WITH_IDEA_CBC_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_DH_anon_WITH_RC4_128_MD5'
        }
        assert expected_ciphers == set([cipher.name for cipher in plugin_result.accepted_cipher_list])

        assert plugin_result.accepted_cipher_list
        assert plugin_result.rejected_cipher_list
        assert not plugin_result.errored_cipher_list

        assert plugin_result.as_text()
        assert plugin_result.as_xml()

        # Ensure the results are pickable so the ConcurrentScanner can receive them via a Queue
        assert pickle.dumps(plugin_result)

    def test_succeeds_when_client_auth_failed_tls_1_2(self):
        # Given a TLS 1.2 server that requires client authentication
        with LegacyOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client does NOT provide a client certificate
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            # OpenSslCipherSuitesPlugin works even when a client cert was not supplied
            plugin = OpenSslCipherSuitesPlugin()
            plugin_result = plugin.process_task(server_info, Tlsv12ScanCommand())

        assert plugin_result.accepted_cipher_list
        assert plugin_result.as_text()
        assert plugin_result.as_xml()

    def test_succeeds_when_client_auth_failed_tls_1_3(self):
        # Given a TLS 1.3 server that requires client authentication
        with ModernOpenSslServer(client_auth_config=ClientAuthConfigEnum.REQUIRED) as server:
            # And the client does NOT provide a client certificate
            server_test = ServerConnectivityTester(
                hostname=server.hostname,
                ip_address=server.ip_address,
                port=server.port
            )
            server_info = server_test.perform()

            # OpenSslCipherSuitesPlugin works even when a client cert was not supplied
            plugin = OpenSslCipherSuitesPlugin()
            plugin_result = plugin.process_task(server_info, Tlsv13ScanCommand())

        assert plugin_result.accepted_cipher_list
        assert plugin_result.as_text()
        assert plugin_result.as_xml()
