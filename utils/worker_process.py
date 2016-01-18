from multiprocessing import Process
from xml.etree.ElementTree import Element

from utils.ssl_connection import SSLConnection


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

            server_info, command, options_dict = task
            # Instantiate the proper plugin
            plugin_instance = self.available_commands[command]()

            try: # Process the task
                result = plugin_instance.process_task(server_info, command, options_dict)
            except Exception as e: # Generate txt and xml results
                # raise
                txt_result = ['Unhandled exception when processing --' +
                              command + ': ', str(e.__class__.__module__) +
                              '.' + str(e.__class__.__name__) + ' - ' + str(e)]
                xml_result = Element(command, exception=txt_result[1], title=plugin_instance.interface.title)
                result = PluginResult(txt_result, xml_result)

            # Send the result to queue_out
            self.queue_out.put((server_info, command, result))
            current_queue_in.task_done()

        return