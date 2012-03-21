#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         sslyze.py
# Purpose:      Main module of SSLyze.
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

from time import time
from multiprocessing import Process, JoinableQueue
import sys

from discover_targets import discover_targets
from discover_plugins import discover_plugins
from parse_command_line import create_command_line_parser, \
    parse_command_line, process_parsing_results, PARSING_ERROR_FORMAT
    


PROG_VERSION =      'SSLyze v0.4'
DEFAULT_NB_PROCESSES =      5 # 10 was too aggressive, lowering it to 5
PLUGIN_PATH =       "plugins"
DEFAULT_TIMEOUT =   5


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
            except Exception as e:
                result = [
                    'Unhandled exception when processing --' + command + ': ',
                     str(e.__class__.__module__) + \
                        '.' + str(e.__class__.__name__) + ' - ' + str(e)]

            # Send the result to queue_out
            self.queue_out.put((target, command, result))
            self.queue_in.task_done()

        return


def _format_title(title):
    return ' ' + title.upper()+ '\n' + ' ' + ('-' * len(title))


def _format_target_results(target, result_list):
    (host, ip, port) = target
    target_result_str = ''

    for (command, task_result_str) in result_list:
        # Print the result of each separate command
        target_result_str += '\n'
        for line in task_result_str:
            target_result_str += line + '\n'

    return _format_title('Scan Results For ' + host + ':' + str(port) + ' - ' \
                + ip + ':' + str(port) ) + '\n' + target_result_str + '\n\n'


def main():

    # Workaround for Cygwin and MAC OS X
    nb_processes = DEFAULT_NB_PROCESSES
    if sys.platform == 'darwin' or sys.platform == 'cygwin':
        print '\nWarning: Running on MAC OS X or Cygwin. Disabling multiprocessing - scans will be slower.'
        nb_processes = 1

    #--PLUGINS INITIALIZATION--
    start_time = time()
    print '\n\n\n' + _format_title('Registering available plugins')
    available_plugins = discover_plugins(PLUGIN_PATH)

    # Create the command line parser and the list of available options
    (parser, available_commands) = create_command_line_parser(
        available_plugins,
        PROG_VERSION,
        DEFAULT_TIMEOUT)

    # Parse the command line
    print '\n\n'
    parse_result = parse_command_line(parser)
    if parse_result == None:
        print PARSING_ERROR_FORMAT.format('No hosts to scan.')
        return
    else:
        (args_command_list, args_target_list) = parse_result

    # Fill the shared settings dictionnary, shared between all the plugins
    shared_settings = process_parsing_results(args_command_list)
    if not shared_settings:
        return


    #--PROCESSES INITIALIZATION--
    task_queue = JoinableQueue() # Processes get tasks from task_queue and
    result_queue = JoinableQueue() # put the result of each task in result_queue

    # Spawn a pool of processes, and pass them the queues
    process_list = []
    for i in xrange(nb_processes):
        p = WorkerProcess(task_queue, result_queue, available_commands, \
                            shared_settings)
        p.start()
        process_list.append(p) # Keep track of the processes that were started


    #--TESTING SECTION--
    # Figure out which hosts are up and fill the task queue with work to do
    print _format_title('Checking host(s) availability')
    alive_target_list = discover_targets(args_target_list, args_command_list,\
                                         available_commands, task_queue)
    print '\n\n'

    # Put a 'None' sentinel in the queue to let the each process know when every
    # task has been completed
    [task_queue.put(None) for process in process_list]

    # Keep track of how many tasks have to be performed for each target
    task_num=0
    for command in available_commands:
        if getattr(args_command_list, command):
            task_num+=1


    # --REPORTING SECTION--
    processes_running = nb_processes

    # Each host has a list of results
    result_dict = {}
    for target in alive_target_list:
        result_dict[target] = []

    # If all processes have stopped, all the work is done
    while processes_running:
        result = result_queue.get()

        if result == None: # Getting None means that one process was done
            processes_running -= 1

        else: # Getting an actual result
            (target, command, task_result_str) = result
            result_dict[target].append((command, task_result_str))

            if len(result_dict[target]) == task_num: # Done with this target
                # Print the results
                print _format_target_results(target, result_dict[target])

        result_queue.task_done()


    # --TERMINATE--
    # Make sure all the processes had time to terminate
    task_queue.join()
    result_queue.join()
    #[process.join() for process in process_list]#Causes interpeter shutdown err
    exec_time = time()-start_time
    print _format_title('Scan Completed in {0:.2f} s'.format(exec_time))


if __name__ == "__main__":
    main()
