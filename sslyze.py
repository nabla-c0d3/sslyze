#!/usr/bin/env python2.7
#-------------------------------------------------------------------------------
# Name:         sslyze.py
# Purpose:      Main module of SSLyze.
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
import re

from time import time
from itertools import cycle
from multiprocessing import Process, JoinableQueue, freeze_support
from xml.etree.ElementTree import Element, tostring
from xml.dom import minidom
import signal
import sys

from plugins import PluginsFinder
from utils.SSLyzeSSLConnection import SSLConnection

try:
    from utils.CommandLineParser import CommandLineParser, CommandLineParsingError
    from utils.ServersConnectivityTester import ServersConnectivityTester, ServerConnectivityError
except ImportError as e:
    print str(e) + '\nERROR: Could not import nassl Python module. Did you clone SSLyze\'s repo ? \n' +\
    'Please download the right pre-compiled package as described in the README.\n'
    sys.exit()


PROJECT_VERSION = '0.13.0'
PROJECT_URL = "https://github.com/nabla-c0d3/sslyze"
PROJECT_EMAIL = 'nabla.c0d3@gmail.com'
PROJECT_DESC = 'Fast and full-featured SSL scanner'

MAX_PROCESSES = 12
MIN_PROCESSES = 3

# Global so we can terminate processes when catching SIGINT
process_list = []


# Todo: Move formatting stuff to another file
SCAN_FORMAT = 'Scan Results For {0}:{1} - {2}:{1}'


class WorkerProcess(Process):

    def __init__(self, priority_queue_in, queue_in, queue_out, available_commands):
        Process.__init__(self)
        self.priority_queue_in = priority_queue_in
        self.queue_in = queue_in
        self.queue_out = queue_out
        self.available_commands = available_commands

    def run(self):
        """
        The process will first complete tasks it gets from self.queue_in.
        Once it gets notified that all the tasks have been completed,
        it terminates.
        """
        from plugins.PluginBase import PluginResult

        # Start processing task in the priority queue first
        current_queue_in = self.priority_queue_in
        while True:

            task = current_queue_in.get() # Grab a task from queue_in
            if task is None: # All tasks have been completed
                current_queue_in.task_done()

                if (current_queue_in == self.priority_queue_in):
                    # All high priority tasks have been completed
                    current_queue_in = self.queue_in # Switch to low priority tasks
                    continue
                else:
                    # All the tasks have been completed
                    self.queue_out.put(None) # Pass on the sentinel to result_queue and exit
                    break

            (target, command, args) = task
            # Instantiate the proper plugin
            plugin_instance = self.available_commands[command]()

            try: # Process the task
                result = plugin_instance.process_task(target, command, args)
            except Exception as e: # Generate txt and xml results
                # raise
                txt_result = ['Unhandled exception when processing --' +
                              command + ': ', str(e.__class__.__module__) +
                              '.' + str(e.__class__.__name__) + ' - ' + str(e)]
                xml_result = Element(command, exception=txt_result[1], title=plugin_instance.interface.title)
                result = PluginResult(txt_result, xml_result)

            # Send the result to queue_out
            self.queue_out.put((target, command, result))
            current_queue_in.task_done()

        return


def _format_title(title):
    return ' {title}\n {underline}\n'.format(title=title.upper(), underline='-' * len(title))


def _format_xml_target_result(server_info, result_list):
    target_xml = Element('target', host=server_info.hostname, ip=server_info.ip_address, port=str(server_info.port))
    result_list.sort(key=lambda result: result[0])  # Sort results

    for (command, plugin_result) in result_list:
        target_xml.append(plugin_result.get_xml_result())

    return target_xml


def _format_txt_target_result(server_info, result_list):
    target_result_str = ''

    for (command, plugin_result) in result_list:
        # Print the result of each separate command
        target_result_str += '\n'
        for line in plugin_result.get_txt_result():
            target_result_str += line + '\n'

    scan_txt = SCAN_FORMAT.format(server_info.hostname, str(server_info.port), server_info.ip_address)
    return _format_title(scan_txt) + '\n' + target_result_str + '\n\n'


def sigint_handler(signum, frame):

    print 'Scan interrupted... shutting down.'
    for (proc, _) in process_list:
        # Terminating a process this way will corrupt the queues but we're shutting down anyway
        proc.terminate()
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
    sslyze_parser = CommandLineParser(available_plugins, PROJECT_VERSION)

    targets_OK = []
    targets_ERR = []

    # Parse the command line
    try:
        good_server_list, bad_server_list, args_command_list = sslyze_parser.parse_command_line()
        targets_ERR.extend(bad_server_list)
    except CommandLineParsingError as e:
        print e.get_error_msg()
        return

    should_print_text_results = not args_command_list.quiet and args_command_list.xml_file != '-'
    if should_print_text_results:
        print '\n\n\n' + _format_title('Available plugins')
        for plugin in available_plugins:
            print '  ' + plugin.__name__
        print '\n\n'



    #--PROCESSES INITIALIZATION--
    # Three processes per target from MIN_PROCESSES up to MAX_PROCESSES
    nb_processes = max(MIN_PROCESSES, min(MAX_PROCESSES, len(good_server_list)*3))
    if args_command_list.https_tunnel:
        nb_processes = 1  # Let's not kill the proxy

    task_queue = JoinableQueue()  # Processes get tasks from task_queue and
    result_queue = JoinableQueue()  # put the result of each task in result_queue

    # Spawn a pool of processes, and pass them the queues
    for _ in xrange(nb_processes):
        priority_queue = JoinableQueue()  # Each process gets a priority queue
        p = WorkerProcess(priority_queue, task_queue, result_queue, available_commands)
        p.start()
        process_list.append((p, priority_queue)) # Keep track of each process and priority_queue


    #--TESTING SECTION--
    # Figure out which hosts are up and fill the task queue with work to do
    if should_print_text_results:
        print _format_title('Checking host(s) availability')

    # Set global network settings
    # TODO: Do this in every processes
    SSLConnection.set_global_network_settings(args_command_list.nb_retries, args_command_list.timeout)


    # Each server gets assigned a priority queue for aggressive commands
    # so that they're never run in parallel against this single server
    cycle_priority_queues = cycle(process_list)
    connectivity_tester = ServersConnectivityTester(good_server_list)
    connectivity_tester.start_connectivity_testing()

    SERVER_OK_FORMAT = '   {host}:{port:<25} => {ip_address}'
    SERVER_INVALID_FORMAT = '   {server_string:<35} => WARNING: {error_msg}; discarding corresponding tasks.'

    for server_connectivity_info in connectivity_tester.get_reachable_servers():
        targets_OK.append(server_connectivity_info)
        if should_print_text_results:
            print SERVER_OK_FORMAT.format(host=server_connectivity_info.hostname, port=server_connectivity_info.port,
                                          ip_address=server_connectivity_info.ip_address)

        # Send tasks to worker processes
        (_, current_priority_queue) = cycle_priority_queues.next()
        for command in available_commands:
            if getattr(args_command_list, command):
                args = args_command_list.__dict__[command]

                if command in sslyze_plugins.get_aggressive_commands():
                    # Aggressive commands should not be run in parallel against
                    # a given server so we use the priority queues to prevent this
                    current_priority_queue.put( (server_connectivity_info, command, args) )
                else:
                    # Normal commands get put in the standard/shared queue
                    task_queue.put( (server_connectivity_info, command, args) )


    for tentative_server_info, exception in connectivity_tester.get_invalid_servers():
        targets_ERR.append(('{}:{}'.format(tentative_server_info.hostname, tentative_server_info.port), exception))


    if should_print_text_results:
        for server_string, exception in targets_ERR:
            if isinstance(exception, ServerConnectivityError):
                print SERVER_INVALID_FORMAT.format(server_string=server_string, error_msg=exception.error_msg)
            else:
                # Unexpected bug in SSLyze
                raise exception
        print '\n\n'

    # Put a 'None' sentinel in the queue to let the each process know when every
    # task has been completed
    for (proc, priority_queue) in process_list:
        task_queue.put(None) # One sentinel in the task_queue per proc
        priority_queue.put(None) # One sentinel in each priority_queue

    # Keep track of how many tasks have to be performed for each target
    task_num = 0
    for command in available_commands:
        if getattr(args_command_list, command):
            task_num += 1


    # --REPORTING SECTION--
    processes_running = nb_processes

    # XML output
    xml_output_list = []

    # Each host has a list of results
    result_dict = {}
    # We cannot use the server_info object directly as its address will change due to multiprocessing
    RESULT_DICT_KEY_FORMAT = '{hostname}:{port}'
    for server_info in targets_OK:
        result_dict[RESULT_DICT_KEY_FORMAT.format(hostname=server_info.hostname, port=server_info.port)] = []

    # If all processes have stopped, all the work is done
    while processes_running:
        result = result_queue.get()

        if result is None: # Getting None means that one process was done
            processes_running -= 1

        else:  # Getting an actual result
            (server_info, command, plugin_result) = result
            result_dict[RESULT_DICT_KEY_FORMAT.format(hostname=server_info.hostname,
                                                      port=server_info.port)].append((command, plugin_result))

            if len(result_dict[RESULT_DICT_KEY_FORMAT.format(hostname=server_info.hostname,
                                                             port=server_info.port)]) == task_num:
                # Done with this server; print the results and update the xml doc
                if args_command_list.xml_file:
                    xml_output_list.append(_format_xml_target_result(
                            server_info, result_dict[RESULT_DICT_KEY_FORMAT.format(hostname=server_info.hostname,
                                                                                   port=server_info.port)]))

                if should_print_text_results:
                    print _format_txt_target_result(
                            server_info, result_dict[RESULT_DICT_KEY_FORMAT.format(hostname=server_info.hostname,
                                                                                   port=server_info.port)])

        result_queue.task_done()


    # --TERMINATE--

    # Make sure all the processes had time to terminate
    task_queue.join()
    result_queue.join()
    #[process.join() for process in process_list] # Causes interpreter shutdown errors
    exec_time = time()-start_time

    # Output XML doc to a file if needed
    if args_command_list.xml_file:
        # TODO: Add proxy and starttls info to each server
        result_xml_attr = {#'httpsTunnel':str(shared_settings['https_tunnel_host']),
                           'totalScanTime': str(exec_time),
                           'networkTimeout': str(args_command_list.timeout),
                           'networkMaxRetries': str(args_command_list.nb_retries),
                           #'startTLS' : str(shared_settings['starttls'])
                           }

        result_xml = Element('results', attrib = result_xml_attr)

        # Sort results in alphabetical order to make the XML files (somewhat) diff-able
        xml_output_list.sort(key=lambda xml_elem: xml_elem.attrib['host'])
        for xml_element in xml_output_list:
            result_xml.append(xml_element)

        xml_final_doc = Element('document', title = "SSLyze Scan Results",
                                SSLyzeVersion = PROJECT_VERSION,
                                SSLyzeWeb = PROJECT_URL)

        # Add the list of invalid targets
        invalid_targets_xml = Element('invalidTargets')
        for server_string, exception in targets_ERR:
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
