#!/usr/bin/env python
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

from time import time
from multiprocessing import Process, JoinableQueue
from xml.etree.ElementTree import Element, tostring
from xml.dom import minidom

from plugins import PluginsFinder
from utils.CommandLineParser import CommandLineParser, CommandLineParsingError
from utils.ServersConnectivityTester import ServersConnectivityTester, \
    ProxyConnectivityTester

SSLYZE_VERSION = 'SSLyze v0.7 beta'
DEFAULT_NB_PROCESSES = 5
DEFAULT_TIMEOUT =   5
PROJECT_URL = "https://github.com/isecPartners/sslyze"

# Todo: Move formatting stuff to another file
SCAN_FORMAT = 'Scan Results For {0}:{1} - {2}:{1}'

class WorkerProcess(Process):

    def __init__(self, queue_in, queue_out, available_commands, shared_settings):
        Process.__init__(self)
        self.queue_in = queue_in
        self.queue_out = queue_out
        self.available_commands = available_commands
        self.shared_settings = shared_settings

    def run(self):
        """
        The process will first complete tasks it gets from self.queue_in.
        Once it gets notified that all the tasks have been completed,
        it terminates.
        """
        from plugins.PluginBase import PluginResult    
        # Plugin classes are unpickled by the multiprocessing module
        # without state info. Need to assign shared_settings here
        for plugin_class in self.available_commands.itervalues():
            plugin_class._shared_settings = self.shared_settings
        
        while True:

            task = self.queue_in.get() # Grab a task from queue_in

            if task == None: # All the tasks have been completed
                self.queue_out.put(None) # Pass on the sentinel to result_queue
                self.queue_in.task_done()
                break

            (target, command, args) = task
            # Instatiate the proper plugin
            plugin_instance = self.available_commands[command]()
                
            try: # Process the task
                result = plugin_instance.process_task(target, command, args)
            except Exception as e: # Generate txt and xml results
                txt_result = ['Unhandled exception when processing --' + 
                              command + ': ', str(e.__class__.__module__) + 
                              '.' + str(e.__class__.__name__) + ' - ' + str(e)]
                xml_result = Element(command, exception=txt_result[1])
                result = PluginResult(txt_result, xml_result)

            # Send the result to queue_out
            self.queue_out.put((target, command, result))
            self.queue_in.task_done()

        return


def _format_title(title):
    return ' ' + title.upper()+ '\n' + ' ' + ('-' * len(title))


def _format_xml_target_result(target, result_list):
    (host, ip, port) = target
    target_xml = Element('target', host=host, ip=ip, port=str(port))
    result_list.sort(key=lambda result: result[0]) # Sort results
    
    for (command, plugin_result) in result_list:
        target_xml.append(plugin_result.get_xml_result())

    return target_xml


def _format_txt_target_result(target, result_list):
    (host, ip, port) = target
    target_result_str = ''

    for (command, plugin_result) in result_list:
        # Print the result of each separate command
        target_result_str += '\n'
        for line in plugin_result.get_txt_result():
            target_result_str += line + '\n'
    
    scan_txt = SCAN_FORMAT.format(host, str(port), ip)
    return _format_title(scan_txt) + '\n' + target_result_str + '\n\n'


def main():

    nb_processes = DEFAULT_NB_PROCESSES

    #--PLUGINS INITIALIZATION--
    start_time = time()
    print '\n\n\n' + _format_title('Registering available plugins')
    sslyze_plugins = PluginsFinder()
    available_plugins = sslyze_plugins.get_plugins()
    available_commands = sslyze_plugins.get_commands()
    print ''
    for plugin in available_plugins:
        print '  ' + plugin.__name__
    print '\n\n'

    # Create the command line parser and the list of available options
    sslyze_parser = CommandLineParser(available_plugins, SSLYZE_VERSION, DEFAULT_TIMEOUT)

    try: # Parse the command line
        (command_list, target_list, shared_settings) = sslyze_parser.parse_command_line()
    except CommandLineParsingError as e:
        print e.get_error_msg()
        return
    

    #--PROCESSES INITIALIZATION--
    if command_list.https_tunnel:
        nb_processes = 1 # Let's not kill the proxy
        
    task_queue = JoinableQueue() # Processes get tasks from task_queue and
    result_queue = JoinableQueue() # put the result of each task in result_queue

    # Spawn a pool of processes, and pass them the queues
    process_list = []
    for _ in xrange(nb_processes):
        p = WorkerProcess(task_queue, result_queue, available_commands, \
                            shared_settings)
        p.start()
        process_list.append(p) # Keep track of the processes that were started


    #--TESTING SECTION--
    # Figure out which hosts are up and fill the task queue with work to do
    print _format_title('Checking host(s) availability')

    if command_list.https_tunnel:
        targets_tester = ProxyConnectivityTester(target_list, 
                                                 command_list.https_tunnel)
    else:
        targets_tester = ServersConnectivityTester(target_list, 
                                                   command_list.starttls,
                                                   command_list.xmpp_to)

    targets_OK = []
    for target in targets_tester.test_connectivity(command_list.timeout):
        # Send tasks to worker processes
        targets_OK.append(target)
        for command in available_commands:
            if getattr(command_list, command):
                args = command_list.__dict__[command]
                task_queue.put( (target, command, args) )
                
    print targets_tester.get_result_str()
    print '\n\n'

    # Put a 'None' sentinel in the queue to let the each process know when every
    # task has been completed
    [task_queue.put(None) for _ in process_list]

    # Keep track of how many tasks have to be performed for each target
    task_num=0
    for command in available_commands:
        if getattr(command_list, command):
            task_num+=1


    # --REPORTING SECTION--
    processes_running = nb_processes
    
    # XML output
    if shared_settings['xml_file']:
        xml_output_list = []

    # Each host has a list of results
    result_dict = {}
    for target in targets_OK:
        result_dict[target] = []

    # If all processes have stopped, all the work is done
    while processes_running:
        result = result_queue.get()

        if result == None: # Getting None means that one process was done
            processes_running -= 1

        else: # Getting an actual result
            (target, command, plugin_result) = result
            result_dict[target].append((command, plugin_result))

            if len(result_dict[target]) == task_num: # Done with this target
                # Print the results and update the xml doc
                print _format_txt_target_result(target, result_dict[target])
                if shared_settings['xml_file']:
                    xml_output_list.append(_format_xml_target_result(target, result_dict[target]))
                           
        result_queue.task_done()


    # --TERMINATE--
    
    # Make sure all the processes had time to terminate
    task_queue.join()
    result_queue.join()
    #[process.join() for process in process_list] # Causes interpreter shutdown errors
    exec_time = time()-start_time
    
    # Output XML doc to a file if needed
    if shared_settings['xml_file']:
        result_xml_attr = {'httpsTunnel':str(shared_settings['https_tunnel_host']),
                           'totalScanTime' : str(exec_time), 
                           'defaultTimeout' : str(shared_settings['timeout']), 
                           'startTLS' : str(shared_settings['starttls'])}
        
        result_xml = Element('results', attrib = result_xml_attr)
        
        # Sort results in alphabetical order to make the XML files (somewhat) diff-able
        xml_output_list.sort(key=lambda xml_elem: xml_elem.attrib['host'])
        for xml_element in xml_output_list:
            result_xml.append(xml_element)
            
        xml_final_doc = Element('document', title = "SSLyze Scan Results",
                                SSLyzeVersion = SSLYZE_VERSION, 
                                SSLyzeWeb = PROJECT_URL)
        xml_final_doc.append(result_xml)

        # Hack: Prettify the XML file so it's (somewhat) diff-able
        xml_final_pretty = minidom.parseString(tostring(xml_final_doc, encoding='UTF-8'))
        with open(shared_settings['xml_file'],'w') as xml_file:
            xml_file.write(xml_final_pretty.toprettyxml(indent="  ", encoding="utf-8" ))
            

    print _format_title('Scan Completed in {0:.2f} s'.format(exec_time))


if __name__ == "__main__":
    main()
