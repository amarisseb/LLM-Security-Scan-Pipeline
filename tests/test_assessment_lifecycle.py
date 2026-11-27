"""Lifecycle regressions: no real workers, models, sockets, or account records."""
import io
import subprocess
import sys
import threading
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch

from app import assessment_api as api
from tools import run_local_agentdojo as launcher


class AssessmentLifecycleTests(unittest.TestCase):
    def setUp(self):
        for name, value in (("_active_jobs", set()), ("_threads", set()),
                            ("_blocked_leases", []), ("_accepting", True)):
            replacement = patch.object(api, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)
        self.process = Mock()
        self.process.poll.return_value = None
        self.process.communicate.return_value = (b"invalid summary", None)
        self.job = Mock()
        self.lease = Mock()
        self.finish = Mock()
        # Replace the native job module as well as Popen; no native handles exist.
        module = types.ModuleType("app.windows_job")
        module.WindowsJob = Mock(return_value=self.job)
        for replacement in (
            patch.dict(sys.modules, {"app.windows_job": module}),
            patch.object(api.subprocess, "Popen", return_value=self.process),
            patch.object(api.subprocess, "CREATE_NO_WINDOW", 0, create=True),
            patch.object(api, "_finish", self.finish),
        ):
            replacement.start()
            self.addCleanup(replacement.stop)

    def run_worker(self):
        api._threads.add(threading.current_thread())
        api._run("run-id", self.lease)

    def assert_reaped(self):
        self.process.kill.assert_called_once_with()
        self.process.wait.assert_called_once_with(timeout=10)
        self.process.stdin.close.assert_called_once_with()
        self.process.stdout.close.assert_called_once_with()
        self.assertNotIn(threading.current_thread(), api._threads)

    def test_failed_assignment_never_releases_launcher_and_reaps_it(self):
        self.job.assign.side_effect = OSError("assignment denied")
        self.run_worker()
        self.process.communicate.assert_not_called()
        self.assert_reaped()
        self.job.close.assert_called_once_with()
        self.finish.assert_called_once()
        self.assertEqual(self.finish.call_args.args[:2], ("run-id", "failed"))
        self.lease.close.assert_called_once_with()
        self.assertFalse(api._active_jobs)

    def test_job_constructor_failure_also_reaps_waiting_launcher(self):
        sys.modules["app.windows_job"].WindowsJob.side_effect = OSError("no job")
        self.run_worker()
        self.process.communicate.assert_not_called()
        self.assert_reaped()
        self.lease.close.assert_called_once_with()

    def test_assignment_precedes_run_handshake(self):
        def released(data, timeout):
            self.job.assign.assert_called_once_with(self.process)
            self.assertIn(self.job, api._active_jobs)
            self.assertEqual((data, timeout), (b"RUN\n", 450))
            return b"invalid summary", None
        self.process.communicate.side_effect = released
        self.run_worker()
        self.process.communicate.assert_called_once()
        self.assert_reaped()

    def test_terminal_status_and_lease_wait_for_tree_and_launcher_cleanup(self):
        events = []
        def tree_cleanup():
            self.finish.assert_not_called()
            self.lease.close.assert_not_called()
            events.append("tree")
        def reap(**kwargs):
            self.finish.assert_not_called()
            self.lease.close.assert_not_called()
            events.append("reap")
        self.job.terminate_and_wait.side_effect = tree_cleanup
        self.process.wait.side_effect = reap
        self.finish.side_effect = lambda *args: events.append("finish")
        self.lease.close.side_effect = lambda: events.append("release")
        self.run_worker()
        self.assertEqual(events, ["tree", "reap", "finish", "release"])

    def test_communication_timeout_still_kills_and_reaps(self):
        self.process.communicate.side_effect = subprocess.TimeoutExpired("worker", 450)
        self.run_worker()
        self.assert_reaped()
        self.job.terminate_and_wait.assert_called_once_with()
        self.assertEqual(self.finish.call_args.args[1], "failed")
        self.lease.close.assert_called_once_with()

    def test_complete_result_is_published_only_after_cleanup(self):
        summary_path = Mock()
        summary_path.parent.parent = (api.ROOT / ".arisec-private/assurance").resolve()
        summary_path.parent.name = "a" * 32
        summary_path.name = "summary.json"
        summary_path.stat.return_value.st_size = 100
        summary_path.read_text.return_value = '{}'
        self.process.communicate.return_value = (b'{"summary":"mock-summary"}', None)
        # Delegate the trusted base path to the real Path implementation.
        real_path = api.Path
        def path(value):
            if value == "mock-summary":
                return types.SimpleNamespace(resolve=lambda: summary_path)
            return real_path(value)
        summary = {"source": "local_benchmark"}
        def published(run_id, status, result):
            self.assertEqual((run_id, status, result), ("run-id", "complete", summary))
            self.job.terminate_and_wait.assert_called_once_with()
            self.process.wait.assert_called_once_with(timeout=10)
            self.lease.close.assert_not_called()
        self.finish.side_effect = published
        with patch.object(api, "Path", side_effect=path), \
                patch.object(api, "_safe_summary", return_value=summary):
            self.run_worker()
        self.finish.assert_called_once()
        self.lease.close.assert_called_once_with()

    def test_unconfirmed_cleanup_retains_lease_and_running_status(self):
        for failure in ("tree", "launcher"):
            with self.subTest(failure=failure):
                self.job.terminate_and_wait.side_effect = TimeoutError() if failure == "tree" else None
                self.process.wait.side_effect = TimeoutError() if failure == "launcher" else None
                self.run_worker()
                self.finish.assert_not_called()
                self.lease.close.assert_not_called()
                self.assertIn(self.lease, api._blocked_leases)
                self.assertNotIn(threading.current_thread(), api._threads)

    def test_launcher_wait_timeout_and_pipe_close_errors_retain_lease_and_deregister(self):
        for stream_name in ("stdin", "stdout"):
            for close_error in (OSError, ValueError):
                with self.subTest(stream=stream_name, close_error=close_error.__name__):
                    self.process.reset_mock()
                    api._blocked_leases.clear()
                    for stream in (self.process.stdin, self.process.stdout):
                        stream.close.side_effect = None
                    self.process.wait.side_effect = subprocess.TimeoutExpired("launcher", 10)
                    getattr(self.process, stream_name).close.side_effect = close_error("pipe close failed")

                    self.run_worker()

                    self.assert_reaped()
                    self.finish.assert_not_called()
                    self.lease.close.assert_not_called()
                    self.assertEqual(api._blocked_leases, [self.lease])
                    self.assertNotIn(self.job, api._active_jobs)

    def test_shutdown_terminates_all_jobs_then_joins_and_rejects_submission(self):
        other_job, worker = Mock(), Mock()
        self.job.terminate_and_wait.side_effect = TimeoutError()
        api._active_jobs.update((self.job, other_job))
        api._threads.add(worker)
        def joined(**kwargs):
            self.assertFalse(api._accepting)
            self.job.terminate_and_wait.assert_called_once_with()
            other_job.terminate_and_wait.assert_called_once_with()
        worker.join.side_effect = joined
        api._shutdown()
        worker.join.assert_called_once_with(timeout=10)
        with patch.object(api.threading, "Thread") as new_thread:
            with self.assertRaises(RuntimeError):
                api._submit("late", self.lease)
            new_thread.assert_not_called()

    def test_worker_queued_before_shutdown_cannot_spawn(self):
        api._accepting = False
        self.run_worker()
        api.subprocess.Popen.assert_not_called()
        self.lease.close.assert_called_once_with()
        self.assertEqual(self.finish.call_args.args[1], "failed")

    def test_thread_start_failure_removes_tracking(self):
        with patch.object(api.threading, "Thread") as thread_type:
            thread_type.return_value.start.side_effect = RuntimeError("cannot start")
            with self.assertRaises(RuntimeError):
                api._submit("run-id", self.lease)
        self.assertFalse(api._threads)

    def test_managed_launcher_rejects_eof_or_wrong_release_before_file_access(self):
        for payload in (b"", b"STOP\n", b"RUN", b"RUN\r\n"):
            with self.subTest(payload=payload), patch.object(sys, "argv", ["launcher", "--managed"]), \
                    patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(payload))), \
                    patch.object(launcher.Path, "read_text") as read, \
                    patch.object(launcher.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RuntimeError, "not released"):
                    launcher.main()
                read.assert_not_called()
                spawn.assert_not_called()

    def test_valid_release_reaches_preparation_without_spawning(self):
        with patch.object(sys, "argv", ["launcher", "--managed"]), \
                patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"RUN\n"))), \
                patch.object(launcher.Path, "read_text", side_effect=FileNotFoundError("unprepared")) as read:
            with self.assertRaises(FileNotFoundError):
                launcher.main()
            read.assert_called_once()
            api.subprocess.Popen.assert_not_called()


class AssessmentLifespanTests(unittest.IsolatedAsyncioTestCase):
    async def test_asgi_shutdown_cleans_assessments_even_when_serving_raises(self):
        from app import main
        # Keep this test independent of housekeeping, accounts and actual workers.
        with patch.object(main, "_housekeeping"), \
                patch.object(main, "_purge_loop", new_callable=AsyncMock), \
                patch.object(api, "startup") as startup, \
                patch.object(api, "_shutdown") as shutdown:
            with self.assertRaisesRegex(RuntimeError, "serving failed"):
                async with main.app.router.lifespan_context(main.app):
                    startup.assert_called_once_with()
                    shutdown.assert_not_called()
                    raise RuntimeError("serving failed")
            shutdown.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
