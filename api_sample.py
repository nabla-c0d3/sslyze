from cryptography.x509 import NameOID

from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand

from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv30ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand, Tlsv11ScanCommand, Tlsv10ScanCommand
from sslyze.synchronous_scanner import SynchronousScanner


def demo_server_connectivity_tester():
    try:
        server_tester = ServerConnectivityTester(
            hostname='smtp.gmail.com',
            port=587,
            tls_wrapped_protocol=TlsWrappedProtocolEnum.STARTTLS_SMTP
        )
        print(f'\nTesting connectivity with {server_tester.hostname}:{server_tester.port}...')
        server_info = server_tester.perform()
    except ServerConnectivityError as e:
        # Could not establish an SSL connection to the server
        raise RuntimeError(f'Could not connect to {e.server_info.hostname}: {e.error_message}')

    return server_info


def demo_synchronous_scanner():
    # Run one scan command to list the server's TLS 1.0 cipher suites
    try:
        server_tester = ServerConnectivityTester(
            hostname='localhost',
            port=443,
            tls_wrapped_protocol=TlsWrappedProtocolEnum.HTTPS
        )
        print(f'\nTesting connectivity with {server_tester.hostname}:{server_tester.port}...')
        server_info = server_tester.perform()
    except ServerConnectivityError as e:
        # Could not establish an SSL connection to the server
        raise RuntimeError(f'Could not connect to {e.server_info.hostname}: {e.error_message}')

    command = Tlsv13ScanCommand()

    synchronous_scanner = SynchronousScanner()

    scan_result = synchronous_scanner.run_scan_command(server_info, command)
    print(scan_result.as_text())


def demo_concurrent_scanner():
    # Setup the server to scan and ensure it is online/reachable
    server_info = demo_server_connectivity_tester()

    # Run multiple scan commands concurrently. It is much faster than the SynchronousScanner
    concurrent_scanner = ConcurrentScanner()

    # Queue some scan commands
    print('\nQueuing some commands...')
    concurrent_scanner.queue_scan_command(server_info, Tlsv12ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, CertificateInfoScanCommand())

    # Process the results
    print('\nProcessing results...')
    for scan_result in concurrent_scanner.get_results():
        # All scan results have the corresponding scan_command and server_info as an attribute
        print(f'\nReceived result for "{scan_result.scan_command.get_title()}" '
              f'on {scan_result.server_info.hostname}')

        # A scan command can fail (as a bug); it is returned as a PluginRaisedExceptionResult
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            raise RuntimeError(f'Scan command failed: {scan_result.scan_command.get_title()}')

        # Each scan result has attributes with the information yo're looking for
        # All these attributes are documented within each scan command's module
        if isinstance(scan_result.scan_command, Tlsv12ScanCommand):
            for cipher in scan_result.accepted_cipher_list:
                print(f'    {cipher.name}')

        elif isinstance(scan_result.scan_command, CertificateInfoScanCommand):
            # Print the Common Names within the verified certificate chain
            if not scan_result.verified_certificate_chain:
                print('Error: certificate chain is not trusted!')
            else:
                print('Certificate chain common names:')
                for cert in scan_result.verified_certificate_chain:
                    cert_common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    print(f'   {cert_common_names[0].value}')


if __name__ == '__main__':
    demo_synchronous_scanner()
    # demo_concurrent_scanner()
