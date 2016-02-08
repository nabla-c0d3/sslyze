# -*- coding: utf-8 -*-
"""The main process class responsible for instantiating and running the plugins.
"""


from multiprocessing import Process
from sslyze.utils.ssl_connection import SSLConnection


class WorkerProcess(Process):

    def __init__(self, priority_queue_in, queue_in, queue_out, available_commands, network_retries, network_timeout):
        Process.__init__(self)
        self.priority_queue_in = priority_queue_in
        self.queue_in = queue_in
        self.queue_out = queue_out
        self.available_commands = available_commands

        # Set global network settings; needs to be done in each process
        SSLConnection.set_global_network_settings(network_retries, network_timeout)

    def run(self):
        """The process will first complete tasks it gets from self.queue_in.
        Once it gets notified that all the tasks have been completed, it terminates.
        """
        from sslyze.plugins.plugin_base import PluginRaisedExceptionResult

        # Start processing task in the priority queue first
        current_queue_in = self.priority_queue_in
        while True:

            task = current_queue_in.get()  # Grab a task from queue_in
            if task is None:  # All tasks have been completed
                current_queue_in.task_done()

                if current_queue_in == self.priority_queue_in:
                    # All high priority tasks have been completed; switch to low priority tasks
                    current_queue_in = self.queue_in
                    continue
                else:
                    # All the tasks have been completed; pass on the sentinel to result_queue and exit
                    self.queue_out.put(None)
                    break

            server_info, command, options_dict = task
            # Instantiate the proper plugin
            plugin_instance = self.available_commands[command]()

            try:
                # Process the task
                result = plugin_instance.process_task(server_info, command, options_dict)
            except Exception as e:
                #raise
                result = PluginRaisedExceptionResult(server_info, command, options_dict, e)

            # Send the result to queue_out
            self.queue_out.put(result)
            current_queue_in.task_done()

        return