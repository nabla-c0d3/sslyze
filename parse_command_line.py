#-------------------------------------------------------------------------------
# Name:         parse_command_line.py
# Purpose:      Command line parsing utilities.
#
# Author:       aaron, alban
#
# Copyright:    2011 SSLyze developers (http://code.google.com/sslyze)
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
#!/usr/bin/env python


from optparse import OptionParser, OptionGroup
from multiprocessing import Manager

def create_command_line_parser(available_plugins, prog_version, timeout):
    """
    Generates the list of possible command line options by calling the
    get_commands() method of available plugins.
    Then, it generates the associated command line parser and returns
    (parser, available_commands).
    """
    usage = 'usage: %prog [options] target1.com target2.com:443 etc...'
    parser = OptionParser(version=prog_version, usage=usage)
    available_commands = {}

    # TODO: Verbose/Debug

    # Client certificate options
    parser.add_option(
        '--cert',
        help='Client certificate filename.',
        dest='cert')
    parser.add_option(
        '--certform',
        help= 'Client certificate format. DER or PEM (default).',
        dest='certform',
        default='PEM')
    parser.add_option(
        '--key',
        help= 'Client private key filename.',
        dest='key')
    parser.add_option(
        '--keyform',
        help= 'Client private key format. DER or PEM (default).',
        dest='keyform',
        default='PEM')
    parser.add_option(
        '--pass',
        help= 'Client private key passphrase.',
        dest='keypass')

    # Timeout
    parser.add_option(
        '--timeout',
        help= (
            'Sets the timeout value in seconds used for every socket '
            'connection made to the target server(s). Default is 5s.'),
        type='int',
        dest='timeout',
        default=timeout)


    # Add plugin options to the parser
    for plugin_class in available_plugins:
        pluginoptiongroup = plugin_class.get_commands()

        # Get the list of commands implemented by the current plugin
        plugin_commands = (zip(*pluginoptiongroup.options))[0]
        # Keep track of which plugin/module supports which command
        for command in plugin_commands:
            available_commands[command] = plugin_class

        # Add the current plugin's options to the parser
        group = OptionGroup(parser, pluginoptiongroup.title,\
                            pluginoptiongroup.description)
        for option in pluginoptiongroup.options:
            # If dest is something.. then we store, otherwise just set True
            if option[2] is not None:
                group.add_option('--' + option[0], action="store",
                                    help=option[1], dest=option[2])
            else:
                group.add_option('--' + option[0], action="store_true",
                                    help=option[1], dest=option[2])
        parser.add_option_group(group)

    # Add the --regular command line parameter as a shortcut
    if parser.has_option('--sslv2') and parser.has_option('--sslv3') \
        and parser.has_option('--tlsv1') and parser.has_option('--reneg') \
        and parser.has_option('--resum') and parser.has_option('--certinfo'):
            parser.add_option(
                '--regular',
                action="store_true",
                help=(
                    'Regular scan. Shortcut for --sslv2 --sslv3 '
                    '--tlsv1 --reneg --resum --certinfo=basic'),
                dest=None)

    return (parser, available_commands)


def parse_command_line(parser):

    (args_command_list, args_target_list) = parser.parse_args()

    if args_target_list == []:
        return

    # Handle the --regular command line parameter as a shortcut
    if parser.has_option('--regular'):
        if getattr(args_command_list, 'regular'):
            setattr(args_command_list, 'regular', False)
            setattr(args_command_list, 'sslv2', True)
            setattr(args_command_list, 'sslv3', True)
            setattr(args_command_list, 'tlsv1', True)
            setattr(args_command_list, 'reneg', True)
            setattr(args_command_list, 'resum', True)
            setattr(args_command_list, 'certinfo', 'basic')

    return (args_command_list, args_target_list)


def process_parsing_results(args_command_list):

    shared_mgr = Manager()
    shared_state = shared_mgr.dict() # Will be sent to every plugin process.

   # Sanity checks on the client cert options
    if bool(args_command_list.cert) ^ bool(args_command_list.key):
        print '   Error=> no private key or certificate file was given! ' + \
                'Use --client_cert and --client_key.\n\n'
        return
    else:
        shared_state['cert'] = args_command_list.cert
        shared_state['key'] = args_command_list.key

    # Parse client cert options
    if args_command_list.certform in ['DER', 'PEM']:
        shared_state['certform'] = args_command_list.certform
    else:
        print '   Error=> --certform should be DER or PEM.\n\n'
        return

    if args_command_list.keyform in ['DER', 'PEM']:
        shared_state['keyform'] = args_command_list.keyform
    else:
        print '   Error=> --keyform should be DER or PEM.\n\n'
        return

    if args_command_list.keypass:
        shared_state['keypass'] = args_command_list.keypass
    else:
        shared_state['keypass'] = None

    # Timeout
    shared_state['timeout'] = args_command_list.timeout

    return shared_state

