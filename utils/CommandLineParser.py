#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         CommandLineParser.py
# Purpose:      Command line parsing utilities for SSLyze.
#
# Author:       aaron, alban
#
# Copyright:    2012 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

from optparse import OptionParser, OptionGroup
from urlparse import urlparse

# Client cert/key checking
from nassl.SslClient import SslClient
from nassl import _nassl, SSL_FILETYPE_ASN1, SSL_FILETYPE_PEM


class CommandLineParsingError(Exception):

    PARSING_ERROR_FORMAT = '  Command line error: {0}\n  Use -h for help.'

    def get_error_msg(self):
        return self.PARSING_ERROR_FORMAT.format(self)


class CommandLineParser():

    # Defines what --regular means
    REGULAR_CMD = ['sslv2', 'sslv3', 'tlsv1', 'tlsv1_1', 'tlsv1_2', 'reneg',
                   'resum', 'certinfo', 'http_get', 'hide_rejected_ciphers',
                   'compression', 'heartbleed']
    SSLYZE_USAGE = 'usage: %prog [options] target1.com target2.com:443 etc...'

    # StartTLS options
    START_TLS_PROTS = ['smtp', 'xmpp', 'pop3', 'ftp', 'imap', 'ldap', 'rdp', 'auto']
    START_TLS_USAGE = 'STARTTLS should be one of: ' + str(START_TLS_PROTS) +  \
        '. The \'auto\' option will cause SSLyze to deduce the protocol' + \
        ' (ftp, imap, etc.) from the supplied port number, for each target servers.'

    # Default values
    DEFAULT_RETRY_ATTEMPTS = 4
    DEFAULT_TIMEOUT = 5


    def __init__(self, available_plugins, sslyze_version):
        """
        Generates SSLyze's command line parser.
        """

        self._parser = OptionParser(version=sslyze_version,
                                    usage=self.SSLYZE_USAGE)

        # Add generic command line options to the parser
        self._add_default_options()

        # Add plugin-specific options to the parser
        self._add_plugin_options(available_plugins)

        # Add the --regular command line parameter as a shortcut if possible
        regular_help = 'Regular HTTPS scan; shortcut for'
        for cmd in self.REGULAR_CMD:
            regular_help += ' --' + cmd
            if cmd == 'certinfo': # gah
                regular_help += '=basic'

            if not self._parser.has_option('--' + cmd):
                return

        self._parser.add_option('--regular', action="store_true", dest=None,
                    help=regular_help)


    def parse_command_line(self):
        """
        Parses the command line used to launch SSLyze.
        """

        (args_command_list, args_target_list) = self._parser.parse_args()

        # Handle the --targets_in command line and fill args_target_list
        if args_command_list.targets_in:
            if args_target_list:
                raise CommandLineParsingError("Cannot use --targets_list and specify targets within the command line.")

            try: # Read targets from a file
                with open(args_command_list.targets_in) as f:
                    for target in f.readlines():
                        if target.strip(): # Ignore empty lines
                            if not target.startswith('#'): # Ignore comment lines
                                args_target_list.append(target.strip())
            except IOError:
                raise CommandLineParsingError("Can't read targets from input file '%s'." %  args_command_list.targets_in)

        if not args_target_list:
            raise CommandLineParsingError('No targets to scan.')

        # Handle the --regular command line parameter as a shortcut
        if self._parser.has_option('--regular'):
            if getattr(args_command_list, 'regular'):
                setattr(args_command_list, 'regular', False)
                for cmd in self.REGULAR_CMD:
                    if cmd=="certinfo":
                        # Allow user to override certinfo when using --regular
                        if getattr(args_command_list, 'certinfo') is None:
                            setattr(args_command_list, 'certinfo', 'basic') # Special case
                    else: 
                        setattr(args_command_list, cmd, True)

        # Create the shared_settings object from looking at the command line
        shared_settings = self._process_parsing_results(args_command_list)
        return args_command_list, args_target_list, shared_settings


    def _add_default_options(self):
        """
        Adds default command line options to the parser.
        """

        # Client certificate options
        clientcert_group = OptionGroup(self._parser,
            'Client certificate support', '')
        clientcert_group.add_option(
            '--cert',
            help='Client certificate filename.',
            dest='cert')
        clientcert_group.add_option(
            '--certform',
            help= 'Client certificate format. DER or PEM (default).',
            dest='certform',
            default='PEM')
        clientcert_group.add_option(
            '--key',
            help= 'Client private key filename.',
            dest='key')
        clientcert_group.add_option(
            '--keyform',
            help= 'Client private key format. DER or PEM (default).',
            dest='keyform',
            default='PEM')
        clientcert_group.add_option(
            '--pass',
            help= 'Client private key passphrase.',
            dest='keypass',
            default='')
        self._parser.add_option_group(clientcert_group)

        # XML output
        self._parser.add_option(
            '--xml_out',
            help='Writes the scan results as an XML document to the file XML_FILE.',
            dest='xml_file',
            default=None)

        # Read targets from input file
        self._parser.add_option(
            '--targets_in',
            help='Reads the list of targets to scan from the file TARGETS_IN. It should contain one host:port per line.',
            dest='targets_in',
            default=None)

        # Timeout
        self._parser.add_option(
            '--timeout',
            help= (
                'Sets the timeout value in seconds used for every socket '
                'connection made to the target server(s). Default is ' +
                str(self.DEFAULT_TIMEOUT) + 's.'),
            type='int',
            dest='timeout',
            default=self.DEFAULT_TIMEOUT)


        # Control connection retry attempts
        self._parser.add_option(
            '--nb_retries',
            help= (
                'Sets the number retry attempts for all network connections '
                'initiated throughout the scan. Increase this value if you are '
                'getting a lot of timeout/connection errors when scanning a '
                'specific server. Decrease this value to increase the speed '
                'of the scans; results may however return connection errors. '
                'Default is '
                + str(self.DEFAULT_RETRY_ATTEMPTS) + ' connection attempts.'),
            type='int',
            dest='nb_retries',
            default=self.DEFAULT_RETRY_ATTEMPTS)


        # HTTP CONNECT Proxy
        self._parser.add_option(
            '--https_tunnel',
            help= (
                'Tunnels all traffic to the target server(s) through an HTTP '
                'CONNECT proxy. HTTP_TUNNEL should be the proxy\'s URL: '
                '\'http://USER:PW@HOST:PORT/\'. For proxies requiring '
                'authentication, only Basic Authentication is supported.'),
            dest='https_tunnel',
            default=None)

        # STARTTLS
        self._parser.add_option(
            '--starttls',
            help= (
                'Performs StartTLS handshakes when connecting to the target '
                'server(s). ' + self.START_TLS_USAGE),
            dest='starttls',
            default=None)

        self._parser.add_option(
            '--xmpp_to',
            help= (
                'Optional setting for STARTTLS XMPP. '
                ' XMPP_TO should be the hostname to be put in the \'to\' attribute '
                'of the XMPP stream. Default is the server\'s hostname.'),
            dest='xmpp_to',
            default=None)

        # Server Name Indication
        self._parser.add_option(
            '--sni',
            help= (
                'Use Server Name Indication to specify the hostname to connect to.'
                ' Will only affect TLS 1.0+ connections.'),
            dest='sni',
            default=None)

    def _add_plugin_options(self, available_plugins):
        """
        Recovers the list of command line options implemented by the available
        plugins and adds them to the command line parser.
        """

        for plugin_class in available_plugins:
            plugin_desc = plugin_class.get_interface()

            # Add the current plugin's commands to the parser
            group = OptionGroup(self._parser, plugin_desc.title,
                                plugin_desc.description)
            for cmd in plugin_desc.get_commands():
                    group.add_option(cmd)

            # Add the current plugin's options to the parser
            for option in plugin_desc.get_options():
                    group.add_option(option)

            self._parser.add_option_group(group)


    def _process_parsing_results(self, args_command_list):
        """
        Performs various sanity checks on the command line that was used to
        launch SSLyze.
        Returns the shared_settings object to be fed to plugins.
        """

        shared_settings = {}
        # Sanity checks on the client cert options
        if bool(args_command_list.cert) ^ bool(args_command_list.key):
            raise CommandLineParsingError('No private key or certificate file were given. See --cert and --key.')

        # Private key and cert formats
        if args_command_list.certform == 'DER':
            args_command_list.certform = SSL_FILETYPE_ASN1
        elif args_command_list.certform == 'PEM':
            args_command_list.certform = SSL_FILETYPE_PEM
        else:
            raise CommandLineParsingError('--certform should be DER or PEM.')

        if args_command_list.keyform == 'DER':
            args_command_list.keyform = SSL_FILETYPE_ASN1
        elif args_command_list.keyform == 'PEM':
            args_command_list.keyform = SSL_FILETYPE_PEM
        else:
            raise CommandLineParsingError('--keyform should be DER or PEM.')

        # Let's try to open the cert and key files
        if args_command_list.cert:
            try:
                open(args_command_list.cert,"r")
            except:
                raise CommandLineParsingError('Could not open the client certificate file "' + str(args_command_list.cert) + '".')

        if args_command_list.key:
            try:
                open(args_command_list.key,"r")
            except:
                raise CommandLineParsingError('Could not open the client private key file "' + str(args_command_list.key) + '"')

            # Try to load the cert and key in OpenSSL
            try:
                sslClient = SslClient()
                sslClient.use_private_key(args_command_list.cert,
                                        args_command_list.certform,
                                        args_command_list.key,
                                        args_command_list.keyform,
                                        args_command_list.keypass)
            except _nassl.OpenSSLError as e:
                if 'bad decrypt' in str(e.args):
                    raise CommandLineParsingError('Could not decrypt the private key. Wrong passphrase ?')
                raise CommandLineParsingError('Could not load the certificate or the private key. Passphrase needed ?')



        # HTTP CONNECT proxy
        shared_settings['https_tunnel_host'] = None
        if args_command_list.https_tunnel:

            # Parse the proxy URL
            parsedUrl = urlparse(args_command_list.https_tunnel)

            if not parsedUrl.netloc:
                raise CommandLineParsingError(
                    'Invalid Proxy URL for --https_tunnel, discarding all tasks.')

            if parsedUrl.scheme in 'http':
               defaultPort = 80
            elif parsedUrl.scheme in 'https':
               defaultPort = 443
            else:
                raise CommandLineParsingError(
                    'Invalid URL scheme for --https_tunnel, discarding all tasks.')

            if not parsedUrl.hostname:
                raise CommandLineParsingError(
                    'Invalid Proxy URL for --https_tunnel, discarding all tasks.')

            try :
                shared_settings['https_tunnel_port'] = parsedUrl.port if parsedUrl.port else defaultPort
            except ValueError: # The supplied port was not a number
                raise CommandLineParsingError(
                    'Invalid Proxy URL for --https_tunnel, discarding all tasks.')

            shared_settings['https_tunnel_host'] = parsedUrl.hostname
            shared_settings['https_tunnel_user'] = parsedUrl.username
            shared_settings['https_tunnel_password'] = parsedUrl.password


        # STARTTLS
        if args_command_list.starttls:
            if args_command_list.starttls not in self.START_TLS_PROTS:
                raise CommandLineParsingError(self.START_TLS_USAGE)

        if args_command_list.starttls and args_command_list.https_tunnel:
            raise CommandLineParsingError(
                'Cannot have --https_tunnel and --starttls at the same time.')

        # Number of connection retries
        if args_command_list.nb_retries < 1:
            raise CommandLineParsingError(
                'Cannot have a number smaller than 1 for --nb_retries.')

        # All good, let's save the data
        for key, value in args_command_list.__dict__.iteritems():
            shared_settings[key] = value

        return shared_settings

