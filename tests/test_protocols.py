import socket

import pytest
from nassl.ssl_client import OpenSslVersionEnum

from sslyze.server_connectivity_tester import ServerConnectivityTester, ClientAuthenticationServerConfigurationEnum
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection, \
    ServerNetworkConfiguration
from sslyze.utils.opportunistic_tls_helpers import ProtocolWithOpportunisticTlsEnum


def _is_ipv6_available() -> bool:
    has_ipv6 = False
    s = socket.socket(socket.AF_INET6)
    try:
        s.connect(('2607:f8b0:4005:804::2004', 443))
        has_ipv6 = True
    except Exception:
        pass
    finally:
        s.close()
    return has_ipv6


class TestProtocols:

    @pytest.mark.skipif(not _is_ipv6_available(), reason='IPv6 not available')
    def test_ipv6(self):
        # Given a server accessible via IPv6
        server_location = ServerNetworkLocationViaDirectConnection(
            hostname='www.google.com',
            port=443,
            ip_address='2607:f8b0:4005:804::2004',
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.openssl_cipher_string_supported

    def test_international_hostname(self):
        # Given a server with non-ascii characters in its hostname
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname='www.sociétégénérale.com',
            port=443,
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.openssl_cipher_string_supported

    def test_xmpp_to(self):
        # Given an XMPP server
        hostname = "talk.google.com"
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname=hostname,
            port=5222,
        )
        network_configuration = ServerNetworkConfiguration(
            tls_server_name_indication=hostname,
            tls_opportunistic_encryption=ProtocolWithOpportunisticTlsEnum.XMPP,
            # That requires a special xmpp_to config
            xmpp_to_hostname='gmail.com',
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location, network_configuration)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.openssl_cipher_string_supported

    @pytest.mark.parametrize(
        "hostname, port, protocol",
        [
            ('smtp.gmail.com', 587, ProtocolWithOpportunisticTlsEnum.SMTP),
            ('imap.comcast.net', 143, ProtocolWithOpportunisticTlsEnum.IMAP),
            ('pop.comcast.net', 110, ProtocolWithOpportunisticTlsEnum.POP3),
            ('ldap.uchicago.edu', 389, ProtocolWithOpportunisticTlsEnum.LDAP),
            ('jabber.org', 5222, ProtocolWithOpportunisticTlsEnum.XMPP_SERVER),
            # Some Heroku Postgres instance I created
            ('ec2-54-75-226-17.eu-west-1.compute.amazonaws.com', 5432, ProtocolWithOpportunisticTlsEnum.POSTGRES)
        ]
    )
    def test_starttls(self, hostname, port, protocol):
        # Given some server using a non-HTTP protocol with StartTLS
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(hostname, port)
        network_configuration = ServerNetworkConfiguration(
            tls_server_name_indication=hostname,
            tls_opportunistic_encryption=protocol,
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location, network_configuration)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.openssl_cipher_string_supported

    def test_optional_client_authentication(self):
        # Given a server that requires a client certificate
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname='client.badssl.com',
            port=443,
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.highest_tls_version_supported
        assert server_info.tls_probing_result.openssl_cipher_string_supported

        # And it detected the client authentication
        assert server_info.tls_probing_result.client_auth_requirement == ClientAuthenticationServerConfigurationEnum.OPTIONAL

    def test_tls_1_only(self):
        # Given a server that only supports TLS 1.0
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
            hostname='tls-v1-0.badssl.com',
            port=1010,
        )

        # When testing connectivity against it
        server_info = ServerConnectivityTester().perform(server_location)

        # It succeeds
        assert server_info.tls_probing_result
        assert server_info.tls_probing_result.client_auth_requirement
        assert server_info.tls_probing_result.openssl_cipher_string_supported

        # And it detected that only TLS 1.0 is supported
        assert server_info.tls_probing_result.highest_tls_version_supported == OpenSslVersionEnum.TLSV1
