from queue import Queue
from uuid import uuid4

from sslyze import ScanCommand
from sslyze.scanner._jobs_worker_thread import JobsWorkerThread, WorkerThreadNoMoreJobsSentinel, QueuedScanJob


class TestJobsWorkerThread:
    def test(self):
        # Given a worker thread that's waiting for jobs to process
        jobs_queue_in = Queue()
        completed_jobs_queue_out = Queue()
        worker_thread = JobsWorkerThread(jobs_queue_in, completed_jobs_queue_out)
        worker_thread.start()

        # And a few jobs to process
        def function_to_call_good(arg1: int, arg2: str) -> str:
            return f"{arg1}-{arg2}"

        job1 = QueuedScanJob(
            parent_server_scan_request_uuid=uuid4(),
            for_scan_command=ScanCommand.CERTIFICATE_INFO,
            function_to_call=function_to_call_good,
            function_arguments=[12, "test"],
        )
        job2 = QueuedScanJob(
            parent_server_scan_request_uuid=uuid4(),
            for_scan_command=ScanCommand.ROBOT,
            function_to_call=function_to_call_good,
            function_arguments=[5, "abc"],
        )
        job3 = QueuedScanJob(
            parent_server_scan_request_uuid=uuid4(),
            for_scan_command=ScanCommand.ELLIPTIC_CURVES,
            function_to_call=function_to_call_good,
            function_arguments=[6, "www"],
        )

        # Including a job that will trigger an error
        def function_to_call_bad(arg1: int, arg2: str) -> str:
            raise ConnectionError()

        job4 = QueuedScanJob(
            parent_server_scan_request_uuid=uuid4(),
            for_scan_command=ScanCommand.CERTIFICATE_INFO,
            function_to_call=function_to_call_bad,
            function_arguments=[12, "test"],
        )
        all_queued_jobs = [job1, job2, job3, job4]

        # When queuing the jobs
        for job in all_queued_jobs:
            jobs_queue_in.put(job)
        jobs_queue_in.put(WorkerThreadNoMoreJobsSentinel())

        # Then the worker thread processes them
        all_completed_jobs = []
        while len(all_completed_jobs) < len(all_queued_jobs):
            completed_job = completed_jobs_queue_out.get(block=True)
            all_completed_jobs.append(completed_job)
            completed_jobs_queue_out.task_done()

        # And the right data was returned
        assert {job.return_value for job in all_completed_jobs} == {None, "12-test", "5-abc", "6-www"}
        exception_was_returned = False

        # And the error was returned
        for completed_job in all_completed_jobs:
            if completed_job.exception:
                assert isinstance(completed_job.exception, ConnectionError)
                exception_was_returned = True
        assert exception_was_returned

        # And the thread was shutdown cleanly
        jobs_queue_in.join()
        completed_jobs_queue_out.join()
        assert not worker_thread.is_alive()
