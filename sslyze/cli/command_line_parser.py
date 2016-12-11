from optparse import OptionParser, OptionGroup

from nassl import SSL_FILETYPE_ASN1, SSL_FILETYPE_PEM

from sslyze.cli import FailedServerScan
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum, ClientAuthenticationCredentials, HttpConnectTunnelingSettings
from sslyze.utils.ssl_connection import SSLConnection


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
                bad_server_list.append(FailedServerScan(server_string, e))
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
