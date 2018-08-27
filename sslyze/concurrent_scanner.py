import random
from _elementtree import Element
from multiprocessing import JoinableQueue

from sslyze.plugins.plugin_base import PluginScanResult
from sslyze.plugins.plugin_base import PluginScanCommand
from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.utils.worker_process import WorkerProcess
from typing import Iterable, Dict
from typing import List


class PluginRaisedExceptionScanResult(PluginScanResult):
    """The result returned when a scan command threw an exception while being run by a ConcurrentScanner.

    Attributes:
        error_message (str): Text-formatted details about the exception that occurred.
    """

    def __init__(
            self,
            server_info: ServerConnectivityInfo,
            scan_command: PluginScanCommand,
            exception: Exception
    ) -> None:
        super().__init__(server_info, scan_command)
        # Cannot keep the full exception as it may not be pickable (ie. _nassl.OpenSSLError)
        self.error_message = '{} - {}'.format(str(exception.__class__.__name__), str(exception))

    ERROR_TXT_FORMAT = 'Unhandled exception while running --{command}:'

    def as_text(self) -> List[str]:
        return [
            self._format_title(self.scan_command.get_title()),
            self.ERROR_TXT_FORMAT.format(command=self.scan_command.get_cli_argument()),
            self.error_message
        ]

    def as_xml(self) -> Element:
        return Element(
            self.scan_command.get_cli_argument(), title=self.scan_command.get_title(), exception=self.as_text()[1]
        )


class ConcurrentScanner:
    """An object to run SSL scanning commands concurrently by dispatching them using a pool of processes.
    """

    _DEFAULT_MAX_PROCESSES_NB = 12
    _DEFAULT_PROCESSES_PER_HOSTNAME_NB = 3

    def __init__(
            self,
            network_retries: int = SynchronousScanner.DEFAULT_NETWORK_RETRIES,
            network_timeout: int = SynchronousScanner.DEFAULT_NETWORK_TIMEOUT,
            max_processes_nb: int = _DEFAULT_MAX_PROCESSES_NB,
            max_processes_per_hostname_nb: int = _DEFAULT_PROCESSES_PER_HOSTNAME_NB
    ) -> None:
        """Create a scanner for running scanning commands concurrently using a pool of processes.

        Args:
            network_retries: How many times SSLyze should retry a connection that timed out.
            network_timeout: The time until an ongoing connection times out.
            max_processes_nb: The maximum number of processes to spawn for running scans concurrently.
            max_processes_per_hostname_nb: The maximum number of processes that can be used for running
                scans concurrently against a single server. A lower value will reduce the chances of DOS-ing the server.
        """
        self._network_retries = network_retries
        self._network_timeout = network_timeout
        self._max_processes_nb = max_processes_nb
        self._max_processes_per_hostname_nb = max_processes_per_hostname_nb

        # Create hostname-specific queues to ensure aggressive scan commands targeting this hostname are never
        # run concurrently
        self._hostname_queues_dict: Dict[str, JoinableQueue] = {}
        self._processes_dict: Dict[str, List[WorkerProcess]] = {}

        self._task_queue: JoinableQueue = JoinableQueue()  # Processes get tasks from task_queue and
        self._result_queue: JoinableQueue = JoinableQueue()  # put the result of each task in result_queue
        self._queued_tasks_nb = 0

    def queue_scan_command(self, server_info: ServerConnectivityInfo, scan_command: PluginScanCommand) -> None:
        """Queue a scan command targeting a specific server.

        Args:
            server_info: The server's connectivity information. The test_connectivity_to_server() method must have been
                called first to ensure that the server is online and accessible.
            scan_command: The scan command to run against this server.
        """
        # Ensure we have the right processes and queues in place for this hostname
        self._check_and_create_process(server_info.hostname)

        # Add the task to the right queue
        self._queued_tasks_nb += 1
        if scan_command.is_aggressive:
            # Aggressive commands should not be run in parallel against
            # a given server so we use the priority queues to prevent this
            self._hostname_queues_dict[server_info.hostname].put((server_info, scan_command))
        else:
            # Normal commands get put in the standard/shared queue
            self._task_queue.put((server_info, scan_command))

    def _check_and_create_process(self, hostname: str) -> None:
        if hostname not in self._hostname_queues_dict.keys():
            # We haven't this hostname before
            if self._get_current_processes_nb() < self._max_processes_nb:
                # Create a new process and new queue for this hostname
                hostname_queue: JoinableQueue = JoinableQueue()
                self._hostname_queues_dict[hostname] = hostname_queue

                process = WorkerProcess(hostname_queue, self._task_queue, self._result_queue, self._network_retries,
                                        self._network_timeout)
                process.start()
                self._processes_dict[hostname] = [process]
            else:
                # We are already using the maximum number of processes
                # Do not create a process and re-use a random existing hostname queue
                self._hostname_queues_dict[hostname] = random.choice(list(self._hostname_queues_dict.values()))
                self._processes_dict[hostname] = []

        else:
            # We have seen this hostname before - create a new process if possible
            if len(self._processes_dict[hostname]) < self._max_processes_per_hostname_nb \
                    and self._get_current_processes_nb() < self._max_processes_nb:
                # We can create a new process; no need to create a queue as it already exists
                process = WorkerProcess(self._hostname_queues_dict[hostname], self._task_queue, self._result_queue,
                                        self._network_retries, self._network_timeout)
                process.start()
                self._processes_dict[hostname].append(process)

    def _get_current_processes_nb(self) -> int:
        return sum([len(process_list) for hostname, process_list in self._processes_dict.items()])

    def get_results(self) -> Iterable[PluginScanResult]:
        """Return the result of previously queued scan commands; new commands cannot be queued once this is called.

        Returns:
            The results of all the scan commands previously queued. Each result will be an instance of the scan
            corresponding command's PluginScanResult subclass. If there was an unexpected error while running the scan
            command, it will be a 'PluginRaisedExceptionScanResult' instance instead.
        """
        # Put a 'None' sentinel in the queue to let the each process know when every task has been completed
        for _ in range(self._get_current_processes_nb()):
            self._task_queue.put(None)

        for hostname, hostname_queue in self._hostname_queues_dict.items():
            for i in range(len(self._processes_dict[hostname])):
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
            for process in process_list:
                process.join()

    def emergency_shutdown(self) -> None:
        # Terminating a process this way will corrupt the queues but we're shutting down anyway
        for process_list in self._processes_dict.values():
            for process in process_list:
                process.terminate()
