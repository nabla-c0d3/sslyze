# -*- coding: utf-8 -*-
"""Utility class to spawn a pool of processes and dispatch scanning commands so they can be run concurrently.
"""

import random
from multiprocessing import JoinableQueue

from sslyze.utils.worker_process import WorkerProcess


class PluginsProcessPool(object):
    """Creates a pool of processes and dispatches scanning commands to be run concurrently.
    """

    DEFAULT_MAX_PROCESSES_NB = 12
    DEFAULT_PROCESSES_PER_HOSTNAME_NB = 3

    # Controls every socket connection done by every plugin
    DEFAULT_NETWORK_RETRIES = 3
    DEFAULT_NETWORK_TIMEOUT = 5  # in seconds

    def __init__(self, available_plugins, network_retries=DEFAULT_NETWORK_RETRIES,
                 network_timeout=DEFAULT_NETWORK_TIMEOUT,
                 max_processes_nb=DEFAULT_MAX_PROCESSES_NB,
                 max_processes_per_hostname_nb=DEFAULT_PROCESSES_PER_HOSTNAME_NB):
        """
        Args:
            available_plugins (PluginsFinder): An object encapsulating the list of available plugins.
            network_retries (Optional[int)]: How many times plugins should retry a connection that timed out.
            network_timeout (Optional[int]): The time until an ongoing connection times out within all plugins.
            max_processes_nb (Optional[int]): The maximum number of processes to spawn for running scans concurrently.
            max_processes_per_hostname_nb (Optional[int]): The maximum of processes that can be used for running scans
                concurrently on a single server.

        Returns:
            PluginsProcessPool: An object for queueing scan commands to be run concurrently.

        """

        self._available_plugins = available_plugins
        self._network_retries = network_retries
        self._network_timeout = network_timeout
        self._max_processes_nb = max_processes_nb
        self._max_processes_per_hostname_nb = max_processes_per_hostname_nb

        # Create hostname-specific queues to ensure aggressive scan commands targeting this hostname are never
        # run concurrently
        self._hostname_queues_dict = {}
        self._processes_dict = {}

        self._task_queue = JoinableQueue()  # Processes get tasks from task_queue and
        self._result_queue = JoinableQueue()  # put the result of each task in result_queue
        self._queued_tasks_nb = 0


    def queue_plugin_task(self, server_connectivity_info, plugin_command, plugin_options_dict={}):
        """Queue a scan command targeting a specific server.

        Args:
            server_connectivity_info (ServerConnectivityInfo): The information for connecting to the server.
            plugin_command (str): The plugin scan command to be run on the server. Available commands for each plugin
                are described in the sslyze CLI --help text.
            plugin_options_dict (dict): Scan options to be passed to the plugin. Available options for each plugin are
                described in the sslyze CLI --help text.
        """
        # Ensure we have the right processes and queues in place for this hostname
        self._check_and_create_process(server_connectivity_info.hostname)

        # Add the task to the right queue
        self._queued_tasks_nb += 1
        if plugin_command in self._available_plugins.get_aggressive_commands():
            # Aggressive commands should not be run in parallel against
            # a given server so we use the priority queues to prevent this
            self._hostname_queues_dict[server_connectivity_info.hostname].put((server_connectivity_info, plugin_command,
                                                                               plugin_options_dict))
        else:
            # Normal commands get put in the standard/shared queue
            self._task_queue.put((server_connectivity_info, plugin_command, plugin_options_dict))


    def _check_and_create_process(self, hostname):
        if hostname not in self._hostname_queues_dict.keys():
            # We haven't this hostname before
            if self._get_current_processes_nb() < self._max_processes_nb:
                # Create a new process and new queue for this hostname
                hostname_queue = JoinableQueue()
                self._hostname_queues_dict[hostname] = hostname_queue

                process = WorkerProcess(hostname_queue, self._task_queue, self._result_queue,
                                        self._available_plugins.get_commands(), self._network_retries,
                                        self._network_timeout)
                process.start()
                self._processes_dict[hostname] = [process]
            else:
                # We are already using the maximum number of processes
                # Do not create a process and re-use a random existing hostname queue
                self._hostname_queues_dict[hostname] = random.choice(self._hostname_queues_dict.values())
                self._processes_dict[hostname] = []

        else:
            # We have seen this hostname before - create a new process if possible
            if len(self._processes_dict[hostname]) < self._max_processes_per_hostname_nb \
                    and self._get_current_processes_nb() < self._max_processes_nb:
                # We can create a new process; no need to create a queue as it already exists
                process = WorkerProcess(self._hostname_queues_dict[hostname], self._task_queue, self._result_queue,
                                        self._available_plugins.get_commands(), self._network_retries,
                                        self._network_timeout)
                process.start()
                self._processes_dict[hostname].append(process)


    def _get_current_processes_nb(self):
        return sum([len(process_list) for hostname, process_list in self._processes_dict.iteritems()])


    def get_results(self):
        """Returns the result of previously queues scan command; new tasks can no longer be queued once this is called.

        Yields:
            PluginResult: The result of a scan command run on a server. The server and command information are available
                within the server_info and plugin_command attributes. The PluginResult object also has
                command/plugin-specific attributes with the result of the scan command that was run; see
                specific PluginResult subclasses for the list of attributes.
        """
        # Put a 'None' sentinel in the queue to let the each process know when every task has been completed
        for _ in xrange(self._get_current_processes_nb()):
            self._task_queue.put(None)

        for hostname, hostname_queue in self._hostname_queues_dict.iteritems():
            for i in xrange(len(self._processes_dict[hostname])):
                hostname_queue.put(None)

        received_task_results = 0
        # Go on until all the tasks have been completed and all processes are done
        expected_task_results = self._queued_tasks_nb + self._get_current_processes_nb()
        while received_task_results != expected_task_results:
            result = self._result_queue.get()
            self._result_queue.task_done()
            received_task_results += 1
            if result is None:
                # Getting None means that one process was done
                pass
            else:
                # Getting an actual result
                yield result

        # Ensure all the queues and processes are done
        self._task_queue.join()
        self._result_queue.join()
        for hostname_queue in self._hostname_queues_dict.values():
            hostname_queue.join()
        for process_list in self._processes_dict.values():
            [process.join() for process in process_list]  # Causes interpreter shutdown errors


    def emergency_shutdown(self):
        # Terminating a process this way will corrupt the queues but we're shutting down anyway
        for process_list in self._processes_dict.values():
            [process.terminate() for process in process_list]