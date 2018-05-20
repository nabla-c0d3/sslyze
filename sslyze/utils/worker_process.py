from multiprocessing import Process
from multiprocessing import JoinableQueue

from sslyze.synchronous_scanner import SynchronousScanner


class WorkerProcess(Process):
    """The main process class responsible for instantiating and running the plugins.
    """

    def __init__(
            self,
            priority_queue_in: JoinableQueue,
            queue_in: JoinableQueue, queue_out: JoinableQueue,
            network_retries: int,
            network_timeout: int
    ) -> None:
        Process.__init__(self)
        self.priority_queue_in = priority_queue_in
        self.queue_in = queue_in
        self.queue_out = queue_out

        # The object that will actually run the scan commands
        self._synchronous_scanner = SynchronousScanner(network_retries, network_timeout)

    def run(self) -> None:
        """The process will first complete tasks it gets from self.queue_in.
        Once it gets notified that all the tasks have been completed, it terminates.
        """
        from sslyze.concurrent_scanner import PluginRaisedExceptionScanResult

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

            server_info, scan_command = task
            try:
                result = self._synchronous_scanner.run_scan_command(server_info, scan_command)
            except Exception as e:
                # raise
                result = PluginRaisedExceptionScanResult(server_info, scan_command, e)

            # Send the result to queue_out
            self.queue_out.put(result)
            current_queue_in.task_done()
