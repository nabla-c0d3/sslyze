# -*- coding: utf-8 -*-
"""Generic, simple thread pool used in some of the plugins.
"""

import threading
from Queue import Queue


class _ThreadPoolSentinel:
    pass


class ThreadPool:
    """
    Generic Thread Pool used in some of the plugins.
    Any unhandled exception happening in the work function goes to the error
    queue that can be read using get_error().
    Anything else goes to the result queue that can be read using get_result().
    """
    def  __init__(self):
        self._active_threads = 0
        self._job_q = Queue()
        self._result_q = Queue()
        self._error_q = Queue()
        self._thread_list = []

    def add_job(self, job):
        self._job_q.put(job)

    def get_error(self):
        active_threads = self._active_threads
        while (active_threads) or (not self._error_q.empty()):
            error = self._error_q.get()
            if isinstance(error, _ThreadPoolSentinel): # One thread was done
                active_threads -= 1
                self._error_q.task_done()
                continue

            else: # Getting an actual error
                self._error_q.task_done()
                yield error


    def get_result(self):
        active_threads = self._active_threads
        while (active_threads) or (not self._result_q.empty()):
            result = self._result_q.get()
            if isinstance(result, _ThreadPoolSentinel): # One thread was done
                active_threads -= 1
                self._result_q.task_done()
                continue

            else: # Getting an actual result
                self._result_q.task_done()
                yield result


    def start(self, nb_threads):
        """
        Should only be called once all the jobs have been added using add_job().
        """
        if self._active_threads:
            raise Exception('Threads already started.')

        # Create thread pool
        for _ in xrange(nb_threads):
            worker = threading.Thread(
                target=_work_function,
                args=(self._job_q, self._result_q, self._error_q))
            worker.start()
            self._thread_list.append(worker)
            self._active_threads += 1

        # Put sentinels to let the threads know when there's no more jobs
        [self._job_q.put(_ThreadPoolSentinel()) for worker in self._thread_list]


    def join(self): # Clean exit
        self._job_q.join()
        [worker.join() for worker in self._thread_list]
        self._active_threads = 0
        self._result_q.join()
        self._error_q.join()


def _work_function(job_q, result_q, error_q):
    """Work function expected to run within threads."""
    while True:
        job = job_q.get()

        if isinstance(job, _ThreadPoolSentinel): # All the work is done, get out
            result_q.put(_ThreadPoolSentinel())
            error_q.put(_ThreadPoolSentinel())
            job_q.task_done()
            break

        function = job[0]
        args = job[1]
        try:
            result = function(*args)
        except Exception as e:
            error_q.put((job, e))
        else:
            result_q.put((job, result))
        finally:
            job_q.task_done()
            
