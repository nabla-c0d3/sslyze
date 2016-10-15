#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
import json
import os
import sys

from sslyze import __version__, PROJECT_URL

# Add ./lib to the path for importing nassl for non-frozen builds
if not hasattr(sys,"frozen"):
    sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))

import re
import signal
from multiprocessing import freeze_support
from time import time
from xml.dom import minidom
from xml.etree.ElementTree import Element, tostring
from sslyze.plugins_process_pool import PluginsProcessPool
from sslyze.plugins_finder import PluginsFinder
from sslyze.server_connectivity import ClientAuthenticationServerConfigurationEnum
from optparse import OptionParser, OptionGroup
from nassl import SSL_FILETYPE_ASN1, SSL_FILETYPE_PEM
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError, ServersConnectivityTester
from sslyze.ssl_settings import TlsWrappedProtocolEnum, ClientAuthenticationCredentials, HttpConnectTunnelingSettings
from sslyze.utils.ssl_connection import SSLConnection


# Global so we can terminate processes when catching SIGINT
plugins_process_pool = None


# Command line parsing utils
class CommandLineParsingError(ValueError):

    PARSING_ERROR_FORMAT = u'  Command line error: {0}\n  Use -h for help.'

    def get_error_msg(self):
        return self.PARSING_ERROR_FORMAT.format(self)


class CommandLineParser(object):

    # Defines what --regular means
    REGULAR_CMD = ['sslv2', 'sslv3', 'tlsv1', 'tlsv1_1', 'tlsv1_2', 'reneg', 'resum', 'certinfo_basic', 'http_get',
                   'hide_rejected_ciphers', 'compression', 'heartbleed', 'openssl_ccs', 'fallback']
    SSLYZE_USAGE = 'usage: %prog [options] target1.com target2.com:443 target3.com:443{ip} etc...'

    # StartTLS options
    START_TLS_PROTOCOLS = ['smtp', 'xmpp', 'xmpp_server', 'pop3', 'ftp', 'imap', 'ldap', 'rdp', 'postgres', 'auto']
    START_TLS_USAGE = 'STARTTLS should be one of: {}. The \'auto\' option will cause SSLyze to deduce the protocol ' \
                      '(ftp, imap, etc.) from the supplied port number, ' \
                      'for each target servers.'.format(' , '.join(START_TLS_PROTOCOLS))

    # Mapping of StartTls protocols and ports; useful for starttls=auto
    STARTTLS_PROTOCOL_DICT = {'smtp': TlsWrappedProtocolEnum.STARTTLS_SMTP,
                              587: TlsWrappedProtocolEnum.STARTTLS_SMTP,
                              25: TlsWrappedProtocolEnum.STARTTLS_SMTP,
                              'xmpp': TlsWrappedProtocolEnum.STARTTLS_XMPP,
                              5222 : TlsWrappedProtocolEnum.STARTTLS_XMPP,
                              'xmpp_server': TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER,
                              5269: TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER,
                              'pop3': TlsWrappedProtocolEnum.STARTTLS_POP3,
                              109: TlsWrappedProtocolEnum.STARTTLS_POP3,
                              110: TlsWrappedProtocolEnum.STARTTLS_POP3,
                              'imap': TlsWrappedProtocolEnum.STARTTLS_IMAP,
                              143: TlsWrappedProtocolEnum.STARTTLS_IMAP,
                              220: TlsWrappedProtocolEnum.STARTTLS_IMAP,
                              'ftp': TlsWrappedProtocolEnum.STARTTLS_FTP,
                              21: TlsWrappedProtocolEnum.STARTTLS_FTP,
                              'ldap': TlsWrappedProtocolEnum.STARTTLS_LDAP,
                              3268: TlsWrappedProtocolEnum.STARTTLS_LDAP,
                              389: TlsWrappedProtocolEnum.STARTTLS_LDAP,
                              'rdp': TlsWrappedProtocolEnum.STARTTLS_RDP,
                              3389: TlsWrappedProtocolEnum.STARTTLS_RDP,
                              'postgres': TlsWrappedProtocolEnum.STARTTLS_POSTGRES,
                              5432: TlsWrappedProtocolEnum.STARTTLS_POSTGRES}

    def __init__(self, available_plugins, sslyze_version):
        """Generates SSLyze's command line parser.
        """

        self._parser = OptionParser(version=sslyze_version, usage=self.SSLYZE_USAGE)

        # Add generic command line options to the parser
        self._add_default_options()

        # Add plugin-specific options to the parser
        self._add_plugin_options(available_plugins)

        # Add the --regular command line parameter as a shortcut if possible
        regular_help = 'Regular HTTPS scan; shortcut for --{}'.format(' --'.join(self.REGULAR_CMD))
        self._parser.add_option('--regular', action="store_true", dest=None, help=regular_help)


    def parse_command_line(self):
        """Parses the command line used to launch SSLyze.
        """

        (args_command_list, args_target_list) = self._parser.parse_args()

        # Handle the --targets_in command line and fill args_target_list
        if args_command_list.targets_in:
            if args_target_list:
                raise CommandLineParsingError("Cannot use --targets_list and specify targets within the command line.")

            try:  # Read targets from a file
                with open(args_command_list.targets_in) as f:
                    for target in f.readlines():
                        if target.strip():  # Ignore empty lines
                            if not target.startswith('#'):  # Ignore comment lines
                                args_target_list.append(target.strip())
            except IOError:
                raise CommandLineParsingError("Can't read targets from input file '{}.".format(
                        args_command_list.targets_in))

        if not args_target_list:
            raise CommandLineParsingError('No targets to scan.')


        # Handle the --regular command line parameter as a shortcut
        if self._parser.has_option('--regular'):
            if getattr(args_command_list, 'regular'):
                setattr(args_command_list, 'regular', False)
                for cmd in self.REGULAR_CMD:
                    setattr(args_command_list, cmd, True)


        # Sanity checks on the command line options
        # Prevent --quiet and --xml_out -
        if args_command_list.xml_file and args_command_list.xml_file == '-' and args_command_list.quiet:
                raise CommandLineParsingError('Cannot use --quiet with --xml_out -.')

        # Prevent --quiet and --json_out -
        if args_command_list.json_file and args_command_list.json_file == '-' and args_command_list.quiet:
                raise CommandLineParsingError('Cannot use --quiet with --json_out -.')

        # Prevent --xml_out - and --json_out -
        if args_command_list.json_file and args_command_list.json_file == '-' \
                and args_command_list.xml_file and args_command_list.xml_file == '-':
                raise CommandLineParsingError('Cannot use --xml_out - with --json_out -.')


        # Sanity checks on the client cert options
        client_auth_creds = None
        if bool(args_command_list.cert) ^ bool(args_command_list.key):
            raise CommandLineParsingError('No private key or certificate file were given. See --cert and --key.')

        elif args_command_list.cert:
            # Private key formats
            if args_command_list.keyform == 'DER':
                key_type = SSL_FILETYPE_ASN1
            elif args_command_list.keyform == 'PEM':
                key_type = SSL_FILETYPE_PEM
            else:
                raise CommandLineParsingError('--keyform should be DER or PEM.')

            # Let's try to open the cert and key files
            try:
                client_auth_creds = ClientAuthenticationCredentials(args_command_list.cert,
                                                                    args_command_list.key,
                                                                    key_type,
                                                                    args_command_list.keypass)
            except ValueError as e:
                raise CommandLineParsingError('Invalid client authentication settings: {}.'.format(e[0]))


        # HTTP CONNECT proxy
        http_tunneling_settings = None
        if args_command_list.https_tunnel:
            try:
                http_tunneling_settings = HttpConnectTunnelingSettings.from_url(args_command_list.https_tunnel)
            except ValueError as e:
                raise CommandLineParsingError('Invalid proxy URL for --https_tunnel: {}.'.format(e[0]))


        # STARTTLS
        tls_wrapped_protocol = TlsWrappedProtocolEnum.PLAIN_TLS
        if args_command_list.starttls:
            if args_command_list.starttls not in self.START_TLS_PROTOCOLS:
                raise CommandLineParsingError(self.START_TLS_USAGE)
            else:
                # StartTLS was specified
                if args_command_list.starttls in self.STARTTLS_PROTOCOL_DICT.keys():
                    # Protocol was given in the command line
                    tls_wrapped_protocol = self.STARTTLS_PROTOCOL_DICT[args_command_list.starttls]


        # Number of connection retries
        if args_command_list.nb_retries < 1:
            raise CommandLineParsingError('Cannot have a number smaller than 1 for --nb_retries.')


        # Create the server connectivity info for each specifed servers
        # A limitation when using the command line is that only one client_auth_credentials and http_tunneling_settings
        # can be specified, for all the servers to scan
        good_server_list = []
        bad_server_list = []
        for server_string in args_target_list:
            # Support unicode domains
            server_string = unicode(server_string, 'utf-8')
            try:
                good_server_list.append(ServerConnectivityInfo.from_command_line(
                    server_string=server_string,
                    tls_wrapped_protocol=tls_wrapped_protocol,
                    tls_server_name_indication=args_command_list.sni,
                    xmpp_to_hostname=args_command_list.xmpp_to,
                    client_auth_credentials=client_auth_creds,
                    http_tunneling_settings=http_tunneling_settings)
                )
            except ServerConnectivityError as e:
                # Will happen for example if the DNS lookup failed or the server string is malformed
                bad_server_list.append((server_string, e))
            except ValueError as e:
                # Will happen for example if xmpp_to is specified for a non-XMPP connection
                raise CommandLineParsingError(e[0])


        # Command line hacks
        # Handle --starttls=auto now that we parsed the server strings
        if args_command_list.starttls == 'auto':
            for server_info in good_server_list:
                # We use the port number to deduce the protocol
                if server_info.port in self.STARTTLS_PROTOCOL_DICT.keys():
                    server_info.tls_wrapped_protocol = self.STARTTLS_PROTOCOL_DICT[server_info.port]

        # Handle --http_get now that we parsed the server strings
        # Doing it here is hacky as the option is defined within PluginOpenSSLCipherSuites
        if args_command_list.http_get:
            for server_info in good_server_list:
                if server_info.port == 443:
                    server_info.tls_wrapped_protocol = TlsWrappedProtocolEnum.HTTPS

        return good_server_list, bad_server_list, args_command_list



    def _add_default_options(self):
        """
        Adds default command line options to the parser.
        """

        # Client certificate options
        clientcert_group = OptionGroup(self._parser,
            'Client certificate support', '')
        clientcert_group.add_option(
            '--cert',
            help='Client certificate chain filename. The certificates must be in PEM format and must be sorted '
                 'starting with the subject\'s client certificate, followed by intermediate CA certificates if '
                 'applicable.',
            dest='cert'
        )
        clientcert_group.add_option(
            '--key',
            help= 'Client private key filename.',
            dest='key'
        )
        clientcert_group.add_option(
            '--keyform',
            help= 'Client private key format. DER or PEM (default).',
            dest='keyform',
            default='PEM'
        )
        clientcert_group.add_option(
            '--pass',
            help= 'Client private key passphrase.',
            dest='keypass',
            default=''
        )
        self._parser.add_option_group(clientcert_group)

        # XML output
        self._parser.add_option(
            '--xml_out',
            help='Writes the scan results as an XML document to the file XML_FILE. If XML_FILE is set to "-", the XML '
                 'output will instead be printed to stdout.',
            dest='xml_file',
            default=None
        )
        # JSON output
        self._parser.add_option(
            '--json_out',
            help='Writes the scan results as a JSON document to the file JSON_FILE. If JSON_FILE is set to "-", the '
                 'JSON output will instead be printed to stdout.',
            dest='json_file',
            default=None
        )
        # Read targets from input file
        self._parser.add_option(
            '--targets_in',
            help='Reads the list of targets to scan from the file TARGETS_IN. It should contain one host:port per '
                 'line.',
            dest='targets_in',
            default=None
        )
        # Timeout
        self._parser.add_option(
            '--timeout',
            help='Sets the timeout value in seconds used for every socket connection made to the target server(s). '
                 'Default is {}s.'.format(str(SSLConnection.NETWORK_TIMEOUT)),
            type='int',
            dest='timeout',
            default=SSLConnection.NETWORK_TIMEOUT
        )
        # Control connection retry attempts
        self._parser.add_option(
            '--nb_retries',
            help='Sets the number retry attempts for all network connections initiated throughout the scan. Increase '
                 'this value if you are getting a lot of timeout/connection errors when scanning a specific server. '
                 'Decrease this value to increase the speed of the scans; results may however return connection errors.'
                 ' Default is {} connection attempts.'.format(str(SSLConnection.NETWORK_MAX_RETRIES)),
            type='int',
            dest='nb_retries',
            default=SSLConnection.NETWORK_MAX_RETRIES
        )
        # HTTP CONNECT Proxy
        self._parser.add_option(
            '--https_tunnel',
            help='Tunnels all traffic to the target server(s) through an HTTP CONNECT proxy. HTTP_TUNNEL should be the '
                 'proxy\'s URL: \'http://USER:PW@HOST:PORT/\'. For proxies requiring authentication, only Basic '
                 'Authentication is supported.',
            dest='https_tunnel',
            default=None
        )
        # STARTTLS
        self._parser.add_option(
            '--starttls',
            help='Performs StartTLS handshakes when connecting to the target server(s). ' + self.START_TLS_USAGE,
            dest='starttls',
            default=None
        )
        self._parser.add_option(
            '--xmpp_to',
            help='Optional setting for STARTTLS XMPP. XMPP_TO should be the hostname to be put in the \'to\' attribute '
                 'of the XMPP stream. Default is the server\'s hostname.',
            dest='xmpp_to',
            default=None
        )
        # Server Name Indication
        self._parser.add_option(
            '--sni',
            help='Use Server Name Indication to specify the hostname to connect to.  Will only affect TLS 1.0+ '
                 'connections.',
            dest='sni',
            default=None
        )
        # No text output
        self._parser.add_option(
            '--quiet',
            action="store_true",
            dest='quiet',
            help='Do not output anything to stdout; useful when using --xml_out or --json_out.'
        )


    def _add_plugin_options(self, available_plugins):
        """Recovers the list of command line options implemented by the available plugins and adds them to the command
        line parser.
        """
        for plugin_class in available_plugins:
            plugin_desc = plugin_class.get_interface()

            # Add the current plugin's commands to the parser
            group = OptionGroup(self._parser, plugin_desc.title, plugin_desc.description)
            for cmd in plugin_desc.get_commands():
                    group.add_option(cmd)

            # Add the current plugin's options to the parser
            for option in plugin_desc.get_options():
                    group.add_option(option)

            self._parser.add_option_group(group)


# Todo: Move formatting stuff to another file
SCAN_FORMAT = u'Scan Results For {0}:{1} - {2}:{1}'


def _format_title(title):
    return u' {title}\n {underline}\n'.format(title=title.upper(), underline='-' * len(title))


TLS_PROTOCOL_XML_TEXT = {
    TlsWrappedProtocolEnum.PLAIN_TLS: 'plainTls',
    TlsWrappedProtocolEnum.HTTPS: 'https',
    TlsWrappedProtocolEnum.STARTTLS_SMTP: 'startTlsSmtp',
    TlsWrappedProtocolEnum.STARTTLS_XMPP: 'startTlsXmpp',
    TlsWrappedProtocolEnum.STARTTLS_XMPP_SERVER: 'startTlsXmppServer',
    TlsWrappedProtocolEnum.STARTTLS_POP3: 'startTlsPop3',
    TlsWrappedProtocolEnum.STARTTLS_IMAP: 'startTlsImap',
    TlsWrappedProtocolEnum.STARTTLS_FTP: 'startTlsFtp',
    TlsWrappedProtocolEnum.STARTTLS_LDAP: 'startTlsLdap',
    TlsWrappedProtocolEnum.STARTTLS_RDP: 'startTlsRdp',
    TlsWrappedProtocolEnum.STARTTLS_POSTGRES: 'startTlsPostGres',
}


def _format_xml_target_result(server_info, result_list):
    target_attrib = {'host': server_info.hostname,
                     'ip': server_info.ip_address,
                     'port': str(server_info.port),
                     'tlsWrappedProtocol': TLS_PROTOCOL_XML_TEXT[server_info.tls_wrapped_protocol]
                     }
    if server_info.http_tunneling_settings:
        # Add proxy settings
        target_attrib['httpsTunnelHostname'] = server_info.http_tunneling_settings.hostname
        target_attrib['httpsTunnelPort'] = str(server_info.http_tunneling_settings.port)

    target_xml = Element('target', attrib=target_attrib)
    result_list.sort(key=lambda result: result)  # Sort results

    for plugin_result in result_list:
        target_xml.append(plugin_result.as_xml())

    return target_xml


def _object_to_json_dict(plugin_object):
    """Convert an object to a dictionnary suitable for the JSON output.
    """
    final_fict = {}
    for key, value in plugin_object.__dict__.iteritems():
        if not key.startswith('_'):
            # Remove private attributes
            final_fict[key] = value
    return final_fict



def _format_json_result(server_info, result_list):
    dict_final = {'server_info': server_info.__dict__}
    dict_command_result = {}
    for plugin_result in result_list:
        dict_result = plugin_result.__dict__
        # Remove the server_info node
        dict_result.pop("server_info", None)
        # Remove the plugin_command node
        plugin_command = dict_result.pop("plugin_command", None)
        dict_command_result[plugin_command] = dict_result

    dict_final['commands_results'] = dict_command_result

    return dict_final



def _format_txt_target_result(server_info, result_list):
    target_result_str = u''

    for plugin_result in result_list:
        # Print the result of each separate command
        target_result_str += '\n'
        for line in plugin_result.as_text():
            target_result_str += line + '\n'

    scan_txt = SCAN_FORMAT.format(server_info.hostname, str(server_info.port), server_info.ip_address)
    return _format_title(scan_txt) + target_result_str + '\n\n'


def sigint_handler(signum, frame):
    print 'Scan interrupted... shutting down.'
    if plugins_process_pool:
        plugins_process_pool.emergency_shutdown()
    sys.exit()


def main():
    # For py2exe builds
    freeze_support()

    # Handle SIGINT to terminate processes
    signal.signal(signal.SIGINT, sigint_handler)

    start_time = time()
    #--PLUGINS INITIALIZATION--
    sslyze_plugins = PluginsFinder()
    available_plugins = sslyze_plugins.get_plugins()
    available_commands = sslyze_plugins.get_commands()

    # Create the command line parser and the list of available options
    sslyze_parser = CommandLineParser(available_plugins, __version__)

    online_servers_list = []
    invalid_servers_list = []

    # Parse the command line
    try:
        good_server_list, bad_server_list, args_command_list = sslyze_parser.parse_command_line()
        invalid_servers_list.extend(bad_server_list)
    except CommandLineParsingError as e:
        print e.get_error_msg()
        return

    should_print_text_results = not args_command_list.quiet and args_command_list.xml_file != '-'  \
        and args_command_list.json_file != '-'
    if should_print_text_results:
        print '\n\n\n' + _format_title('Available plugins')
        for plugin in available_plugins:
            print '  ' + plugin.__name__
        print '\n\n'


    #--PROCESSES INITIALIZATION--
    if args_command_list.https_tunnel:
        # Maximum one process to not kill the proxy
        plugins_process_pool = PluginsProcessPool(sslyze_plugins, args_command_list.nb_retries,
                                                  args_command_list.timeout, max_processes_nb=1)
    else:
        plugins_process_pool = PluginsProcessPool(sslyze_plugins, args_command_list.nb_retries,
                                                  args_command_list.timeout)

    #--TESTING SECTION--
    # Figure out which hosts are up and fill the task queue with work to do
    if should_print_text_results:
        print _format_title('Checking host(s) availability')

    connectivity_tester = ServersConnectivityTester(good_server_list)
    connectivity_tester.start_connectivity_testing(network_timeout=args_command_list.timeout)

    SERVER_OK_FORMAT = u'   {host}:{port:<25} => {ip_address} {client_auth_msg}'
    SERVER_INVALID_FORMAT = u'   {server_string:<35} => WARNING: {error_msg}; discarding corresponding tasks.'

    # Store and print servers we were able to connect to
    for server_connectivity_info in connectivity_tester.get_reachable_servers():
        online_servers_list.append(server_connectivity_info)
        if should_print_text_results:
            client_auth_msg = ''
            client_auth_requirement = server_connectivity_info.client_auth_requirement
            if client_auth_requirement == ClientAuthenticationServerConfigurationEnum.REQUIRED:
                client_auth_msg = '  WARNING: Server REQUIRED client authentication, specific plugins will fail.'
            elif client_auth_requirement == ClientAuthenticationServerConfigurationEnum.OPTIONAL:
                client_auth_msg = '  WARNING: Server requested optional client authentication'

            print SERVER_OK_FORMAT.format(host=server_connectivity_info.hostname, port=server_connectivity_info.port,
                                          ip_address=server_connectivity_info.ip_address,
                                          client_auth_msg=client_auth_msg)

        # Send tasks to worker processes
        for plugin_command in available_commands:
            if getattr(args_command_list, plugin_command):
                # Get this plugin's options if there's any
                plugin_options_dict = {}
                for option in available_commands[plugin_command].get_interface().get_options():
                    # Was this option set ?
                    if getattr(args_command_list,option.dest):
                        plugin_options_dict[option.dest] = getattr(args_command_list, option.dest)

                plugins_process_pool.queue_plugin_task(server_connectivity_info, plugin_command, plugin_options_dict)


    for tentative_server_info, exception in connectivity_tester.get_invalid_servers():
        invalid_servers_list.append((tentative_server_info.server_string, exception))


    # Print servers we were NOT able to connect to
    if should_print_text_results:
        for server_string, exception in invalid_servers_list:
            if isinstance(exception, ServerConnectivityError):
                print SERVER_INVALID_FORMAT.format(server_string=server_string, error_msg=exception.error_msg)
            else:
                # Unexpected bug in SSLyze
                raise exception
        print '\n\n'

    # Keep track of how many tasks have to be performed for each target
    task_num = 0
    for command in available_commands:
        if getattr(args_command_list, command):
            task_num += 1


    # --REPORTING SECTION--
    # XML output
    xml_output_list = []

    # Each host has a list of results
    result_dict = {}
    # We cannot use the server_info object directly as its address will change due to multiprocessing
    RESULT_KEY_FORMAT = u'{hostname}:{ip_address}:{port}'.format
    for server_info in online_servers_list:
        result_dict[RESULT_KEY_FORMAT(hostname=server_info.hostname, ip_address=server_info.ip_address,
                                      port=server_info.port)] = []

    # Process the results as they come
    for plugin_result in plugins_process_pool.get_results():
        server_info = plugin_result.server_info
        result_dict[RESULT_KEY_FORMAT(hostname=server_info.hostname, ip_address=server_info.ip_address,
                                      port=server_info.port)].append(plugin_result)

        result_list = result_dict[RESULT_KEY_FORMAT(hostname=server_info.hostname, ip_address=server_info.ip_address,
                                                    port=server_info.port)]

        if len(result_list) == task_num:
            # Done with this server; print the results and update the xml doc
            if args_command_list.xml_file:
                xml_output_list.append(_format_xml_target_result(server_info, result_list))

            if should_print_text_results:
                print _format_txt_target_result(server_info, result_list)


    # --TERMINATE--
    exec_time = time()-start_time

    # Output JSON to a file if needed
    if args_command_list.json_file:
        json_output = {'total_scan_time': str(exec_time),
                       'network_timeout': str(args_command_list.timeout),
                       'network_max_retries': str(args_command_list.nb_retries),
                       'invalid_targets': [],
                       'accepted_targets': []}

        # Add the list of invalid targets
        for server_string, exception in invalid_servers_list:
            if isinstance(exception, ServerConnectivityError):
                json_output['invalid_targets'].append({server_string: exception.error_msg})
            else:
                # Unexpected bug in SSLyze
                raise exception

        # Add the output of the plugins for each server
        for host_str, plugin_result_list in result_dict.iteritems():
            server_info = plugin_result_list[0].server_info
            json_output['accepted_targets'].append(_format_json_result(server_info, plugin_result_list))

        final_json_output = json.dumps(json_output, default=_object_to_json_dict, sort_keys=True, indent=4)
        if args_command_list.json_file == '-':
            # Print XML output to the console if needed
            print final_json_output
        else:
            # Otherwise save the XML output to the console
            with open(args_command_list.json_file, 'w') as json_file:
                json_file.write(final_json_output)


    # Output XML doc to a file if needed
    if args_command_list.xml_file:
        result_xml_attr = {'totalScanTime': str(exec_time),
                           'networkTimeout': str(args_command_list.timeout),
                           'networkMaxRetries': str(args_command_list.nb_retries)}
        result_xml = Element('results', attrib = result_xml_attr)

        # Sort results in alphabetical order to make the XML files (somewhat) diff-able
        xml_output_list.sort(key=lambda xml_elem: xml_elem.attrib['host'])
        for xml_element in xml_output_list:
            result_xml.append(xml_element)

        xml_final_doc = Element('document', title="SSLyze Scan Results", SSLyzeVersion=__version__,
                                SSLyzeWeb=PROJECT_URL)

        # Add the list of invalid targets
        invalid_targets_xml = Element('invalidTargets')
        for server_string, exception in invalid_servers_list:
            if isinstance(exception, ServerConnectivityError):
                error_xml = Element('invalidTarget', error=exception.error_msg)
                error_xml.text = server_string
                invalid_targets_xml.append(error_xml)
            else:
                # Unexpected bug in SSLyze
                raise exception
        xml_final_doc.append(invalid_targets_xml)

        # Add the output of the plugins
        xml_final_doc.append(result_xml)

        # Remove characters that are illegal for XML
        # https://lsimons.wordpress.com/2011/03/17/stripping-illegal-characters-out-of-xml-in-python/
        xml_final_string = tostring(xml_final_doc, encoding='UTF-8')
        illegal_xml_chars_RE = re.compile(u'[\x00-\x08\x0b\x0c\x0e-\x1F\uD800-\uDFFF\uFFFE\uFFFF]')
        xml_sanitized_final_string = illegal_xml_chars_RE.sub('', xml_final_string)

        # Hack: Prettify the XML file so it's (somewhat) diff-able
        xml_final_pretty = minidom.parseString(xml_sanitized_final_string).toprettyxml(indent="  ", encoding="utf-8" )

        if args_command_list.xml_file == '-':
            # Print XML output to the console if needed
            print xml_final_pretty
        else:
            # Otherwise save the XML output to the console
            with open(args_command_list.xml_file, 'w') as xml_file:
                xml_file.write(xml_final_pretty)


    if should_print_text_results:
        print _format_title('Scan Completed in {0:.2f} s'.format(exec_time))


if __name__ == "__main__":
    main()
