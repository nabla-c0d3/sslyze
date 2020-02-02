from faker import Faker
from faker.providers import internet
from nassl.ssl_client import OpenSslVersionEnum

from sslyze.server_connectivity import ServerConnectivityInfo, ServerTlsProbingResult, \
    ClientAuthRequirementEnum
from sslyze.server_setting import ServerNetworkLocationViaDirectConnection, ServerNetworkConfiguration


fake = Faker()
fake.add_provider(internet)


class ServerConnectivityInfoFactory:

    @staticmethod
    def create():
        server_location = ServerNetworkLocationViaDirectConnection(
            hostname=fake.hostname(),
            port=443,
            ip_address=fake.ipv4_private()
        )
        return ServerConnectivityInfo(
            server_location=server_location,
            network_configuration=ServerNetworkConfiguration(
                tls_server_name_indication=server_location.hostname
            ),
            tls_probing_result=ServerTlsProbingResult(
                highest_tls_version_supported=OpenSslVersionEnum.TLSV1_2,
                cipher_suite_supported="AES",
                client_auth_requirement=ClientAuthRequirementEnum.DISABLED
            ),
        )
