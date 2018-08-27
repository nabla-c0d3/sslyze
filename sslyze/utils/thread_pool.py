import threading
from collections import Callable
from typing import Tuple, Any, List, Iterable

from queue import Queue


class _ThreadPoolSentinel:
    pass


JobType = Tuple[Callable, List]  # A function and its arguments


class ThreadPool:
    """Generic Thread Pool used in some of the plugins.

    Any unhandled exception happening in the work function goes to the error queue that can be read using get_error().
    Anything else goes to the result queue that can be read using get_result().
    """
    def __init__(self) -> None:
        self._active_threads = 0
        self._job_q: Queue = Queue()
        self._result_q: Queue = Queue()
        self._error_q: Queue = Queue()
        self._thread_list: List[threading.Thread] = []

    def add_job(self, job: JobType) -> None:
        self._job_q.put(job)

    def get_error(self) -> Iterable[Tuple[JobType, Exception]]:
        active_threads = self._active_threads
        while active_threads or (not self._error_q.empty()):
            error = self._error_q.get()
            if isinstance(error, _ThreadPoolSentinel):
                # One thread was done
                active_threads -= 1
                self._error_q.task_done()
                continue

            else:
                # Getting an actual error
                self._error_q.task_done()
                yield error

    def get_result(self) -> Iterable[Tuple[JobType, Any]]:
        active_threads = self._active_threads
        while active_threads or (not self._result_q.empty()):
            result = self._result_q.get()
            if isinstance(result, _ThreadPoolSentinel):
                # One thread was done
                active_threads -= 1
                self._result_q.task_done()
                continue

            else:
                # Getting an actual result
                self._result_q.task_done()
                yield result

    def start(self, nb_threads: int) -> None:
        """Should only be called once all the jobs have been added using add_job().
        """
        if self._active_threads:
            raise Exception('Threads already started.')

        # Create thread pool
        for _ in range(nb_threads):
            worker = threading.Thread(
                target=_work_function,
                args=(self._job_q, self._result_q, self._error_q))
            worker.start()
            self._thread_list.append(worker)
            self._active_threads += 1

        # Put sentinels to let the threads know when there's no more jobs
        for _ in self._thread_list:
            self._job_q.put(_ThreadPoolSentinel())

    def join(self) -> None:
        # Clean exit
        self._job_q.join()

        for worker in self._thread_list:
            worker.join()
        self._thread_list = []

        self._active_threads = 0
        self._result_q.join()
        self._error_q.join()


def _work_function(job_q: Queue, result_q: Queue, error_q: Queue) -> None:
    """Work function expected to run within threads.
    """
    while True:
        job = job_q.get()

        if isinstance(job, _ThreadPoolSentinel):
            # All the work is done, get out
            result_q.put(_ThreadPoolSentinel())
            error_q.put(_ThreadPoolSentinel())
            job_q.task_done()
            break

        work_function = job[0]
        args = job[1]
        try:
            result = work_function(*args)
        except Exception as e:
            error_q.put((job, e))
        else:
            result_q.put((job, result))
        finally:
            job_q.task_done()
