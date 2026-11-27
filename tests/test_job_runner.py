import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from app import job_runner as runner


class ExecutorTests(unittest.TestCase):
    def test_concurrent_reservations_and_release_once(self):
        executor = runner.BoundedScanExecutor(max_pending=4)
        self.addCleanup(executor.shutdown)
        with concurrent.futures.ThreadPoolExecutor(16) as callers:
            leases = list(callers.map(lambda _: executor.reserve(), range(64)))
        admitted = [lease for lease in leases if lease is not None]
        self.assertEqual(len(admitted), 4)
        for lease in admitted:
            self.assertTrue(lease.release())
            self.assertFalse(lease.release())
        self.assertIsNotNone(executor.reserve())

    def test_running_and_cancelled_jobs_hold_capacity(self):
        executor = runner.BoundedScanExecutor(max_pending=2)
        gate = threading.Event()
        self.addCleanup(executor.shutdown)
        self.addCleanup(gate.set)
        first, second = executor.reserve(), executor.reserve()
        future = executor.submit_reserved(first, gate.wait)
        pending = executor.submit_reserved(second, lambda: None)
        self.assertFalse(first.release())
        self.assertIsNone(executor.reserve())
        self.assertTrue(pending.cancel())
        replacement = executor.reserve()
        self.assertIsNotNone(replacement)
        replacement.release()
        gate.set()
        future.result(2)

    def test_submission_and_execution_failures_release(self):
        executor = runner.BoundedScanExecutor(max_pending=1)
        self.addCleanup(executor.shutdown)
        lease = executor.reserve()
        with patch.object(executor._pool, "submit", side_effect=RuntimeError()):
            with self.assertRaises(RuntimeError):
                executor.submit_reserved(lease, lambda: None)
        lease = executor.reserve()
        future = executor.submit_reserved(lease, lambda: 1 / 0)
        with self.assertRaises(ZeroDivisionError):
            future.result(2)
        # result() may precede the done callback on another thread.
        limit = time.monotonic() + 2
        while time.monotonic() < limit:
            lease = executor.reserve()
            if lease:
                break
        self.assertIsNotNone(lease)
        self.assertTrue(lease.release())
        with self.assertRaises(ValueError):
            executor.submit_reserved(lease, lambda: None)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_fixture(self, code, *, timeout=3, payload=None, progress=None):
        command = [sys.executable, "-c", code]
        with patch.object(runner, "_worker_command", return_value=command):
            return runner.run_isolated_job("api", "test", payload or {}, self.root,
                                           timeout, on_progress=progress)

    def test_stdin_credentials_progress_and_success(self):
        code = """
import json,sys,os
from pathlib import Path
j=json.loads(sys.stdin.readline())
assert j['payload']['api_key']=='unique-test-secret'
assert 'unique-test-secret' not in repr(sys.argv)
assert 'unique-test-secret' not in repr(dict(os.environ))
p=Path(j['output_dir'])/'ok.report.jsonl'; p.write_text('{}')
print(json.dumps(dict(type='progress',index=1,total=1,probe='probes.test')),flush=True)
print(json.dumps(dict(type='result',report_path=str(p))),flush=True)
"""
        events = []
        result = self.run_fixture(code, payload={"api_key": "unique-test-secret"}, progress=lambda *args: events.append(args))
        self.assertEqual(result, (self.root / "ok.report.jsonl").resolve())
        self.assertEqual(events[0], (1, 1, "probes.test"))

    def test_hung_worker_and_descendant_killed(self):
        pidfile = self.root / "pids"
        code = """
import json,sys,subprocess,time,os
from pathlib import Path
j=json.loads(sys.stdin.readline())
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])
(Path(j['output_dir'])/'pids').write_text(str(os.getpid())+' '+str(child.pid))
time.sleep(60)
"""
        started = time.monotonic()
        with self.assertRaises(runner.WorkerTimedOut):
            self.run_fixture(code, timeout=1)
        self.assertLess(time.monotonic() - started, 8)
        self.assertTrue(pidfile.exists())
        for pid in map(int, pidfile.read_text().split()):
            if os.name == "nt":
                import ctypes
                from ctypes import wintypes
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                kernel.OpenProcess.restype = wintypes.HANDLE
                kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                handle = kernel.OpenProcess(0x1000, False, pid)
                if handle:
                    try:
                        status = wintypes.DWORD()
                        self.assertTrue(kernel.GetExitCodeProcess(handle, ctypes.byref(status)))
                        self.assertNotEqual(status.value, 259)
                    finally:
                        kernel.CloseHandle(handle)
            else:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                stat = Path(f"/proc/{pid}/stat")
                self.assertTrue(stat.exists() and stat.read_text().split()[2] == "Z")

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects")
    def test_job_cleanup_polling_is_bounded_and_handle_closes(self):
        from app import windows_job
        job = windows_job.WindowsJob()
        self.addCleanup(job.close)

        def still_active(handle, info_class, buffer, size, returned):
            buffer._obj.ActiveProcesses = 1
            return 1

        with patch.object(windows_job._kernel, "TerminateJobObject", return_value=1), \
             patch.object(windows_job._kernel, "QueryInformationJobObject", side_effect=still_active) as query:
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                job.terminate_and_wait(timeout=.03)
            self.assertLess(time.monotonic() - started, 1)
            self.assertGreater(query.call_count, 1)
        job.close()
        self.assertIsNone(job.handle)

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects")
    def test_assignment_failure_does_not_send_stdin(self):
        from app.windows_job import WindowsJob
        code = "import sys; from pathlib import Path; sys.stdin.readline(); Path(" + repr(str(self.root / "started")) + ").touch()"
        with patch.object(WindowsJob, "assign", side_effect=OSError("denied")):
            with self.assertRaises(runner.WorkerFailure) as caught:
                self.run_fixture(code)
        self.assertEqual(caught.exception.code, "worker_start_failed")
        self.assertFalse((self.root / "started").exists())

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects")
    def test_normal_completion_waits_for_descendant_termination(self):
        from app.windows_job import WindowsJob
        observed = []
        original = WindowsJob.terminate_and_wait

        def cleanup(job, timeout=5):
            original(job, timeout)
            observed.append(True)

        code = """
import json,sys,subprocess
from pathlib import Path
j=json.loads(sys.stdin.readline())
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'], stdout=subprocess.DEVNULL)
(Path(j['output_dir'])/'child').write_text(str(child.pid))
p=Path(j['output_dir'])/'ok.report.jsonl'; p.write_text('{}')
print(json.dumps(dict(type='result',report_path=str(p))),flush=True)
"""
        with patch.object(WindowsJob, "terminate_and_wait", cleanup):
            self.run_fixture(code)
        self.assertEqual(observed, [True])
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, int((self.root / "child").read_text()))
        if handle:
            try:
                status = wintypes.DWORD()
                self.assertTrue(kernel.GetExitCodeProcess(handle, ctypes.byref(status)))
                self.assertNotEqual(status.value, 259)
            finally:
                kernel.CloseHandle(handle)

    def test_malformed_oversized_and_failure_are_coarse(self):
        for code in ["print('secret-not-json')", "print('x'*1000000)",
                     "print('{\"type\":\"error\",\"code\":\"secret\"}')",
                     "print('[]')", "raise RuntimeError('secret')"]:
            with self.subTest(code=code), self.assertRaises(runner.WorkerFailure) as caught:
                self.run_fixture(code)
            self.assertNotIn("secret", str(caught.exception))

    def test_report_must_exist_and_stay_inside_output(self):
        outside = self.root.parent / "outside.report.jsonl"
        for report in [outside, self.root / "missing.report.jsonl", self.root / "wrong.txt"]:
            code = "import json; print(json.dumps(dict(type='result',report_path=" + repr(str(report)) + ")))"
            with self.subTest(report=report), self.assertRaises(runner.WorkerFailure):
                self.run_fixture(code)

    def test_payload_bound_prevents_spawn(self):
        with patch.object(runner.subprocess, "Popen") as spawn:
            with self.assertRaises(runner.WorkerFailure):
                runner.run_isolated_job("api", "test", {"key": "x" * runner.MAX_JOB_BYTES}, self.root, 1)
            spawn.assert_not_called()

    def test_real_worker_rejects_invalid_job(self):
        child = subprocess.run([sys.executable, "-m", "app.scan_worker"],
                               input=b'{}\n', capture_output=True, timeout=5)
        self.assertEqual(json.loads(child.stdout), {"type": "error", "code": "invalid_job"})
        self.assertEqual(child.stderr, b"")

    def test_http_dispatch_matches_main_payload(self):
        from app import scan_worker
        from types import SimpleNamespace
        from unittest.mock import Mock
        engine = Mock(return_value=self.root / "ok.report.jsonl")
        lab = Mock()
        payload = dict(url="http://127.0.0.1:8080/chat", template={"message": "{{prompt}}"},
                       response_path="text", token="secret", prompt_cap=2,
                       lab_targets=["http://127.0.0.1:8080/chat"])
        with patch.dict(sys.modules, {"app.application_scan": SimpleNamespace(run_application_scan=engine)}), patch("app.lab_policy.configure_local_targets", lab):
            scan_worker._run(dict(kind="http", payload=payload, output_dir=str(self.root)), None)
        lab.assert_called_once_with(payload["lab_targets"])
        engine.assert_called_once_with(payload["url"], payload["template"], "text", "secret",
                                       self.root, on_progress=None, prompt_cap=2)

    def test_worker_environment_drops_credentials_and_config(self):
        environment = dict(OPENAI_API_KEY="secret", GOOGLE_APPLICATION_CREDENTIALS="secret.json",
                           AWS_SHARED_CREDENTIALS_FILE="credentials", RUST_LOG="trace",
                           PYTHONPATH="injection", HTTPS_PROXY="http://secret", HF_TOKEN="secret",
                           PYTHONIOENCODING="ascii", XDG_CACHE_HOME=str(self.root))
        code = """
import os,json,sys
from pathlib import Path
j=json.loads(sys.stdin.readline())
assert os.environ['PYTHONIOENCODING']=='utf-8'
assert 'XDG_CACHE_HOME' in os.environ
assert not any(k in os.environ for k in ['OPENAI_API_KEY','GOOGLE_APPLICATION_CREDENTIALS','AWS_SHARED_CREDENTIALS_FILE','RUST_LOG','PYTHONPATH','HTTPS_PROXY','HF_TOKEN'])
p=Path(j['output_dir'])/'ok.report.jsonl'; p.write_text('{}')
print(json.dumps(dict(type='result',report_path=str(p))))
"""
        with patch.dict(os.environ, environment):
            self.run_fixture(code)

    def test_child_error_codes_do_not_leak_exception_text(self):
        from app.scan_worker import _ERROR_CODES
        for name, expected in {**_ERROR_CODES, "UnsafeRedirect": "scan_failed"}.items():
            code = ("from app import scan_worker as w\n"
                    "def fail(*args):\n"
                    "    raise type(" + repr(name) + ", (Exception,), {})('credential-secret')\n"
                    "w._run=fail\nraise SystemExit(w.main())\n")
            with self.subTest(name=name), self.assertRaises(runner.WorkerFailure) as caught:
                self.run_fixture(code)
            self.assertEqual(caught.exception.code, expected)
            self.assertNotIn("credential-secret", str(caught.exception))

    def test_128k_request_plus_metadata_fits(self):
        code = """
import sys,json
from pathlib import Path
j=json.loads(sys.stdin.readline())
assert len(j['payload']['template'])==128*1024
p=Path(j['output_dir'])/'ok.report.jsonl'; p.write_text('{}')
print(json.dumps(dict(type='result',report_path=str(p))))
"""
        self.run_fixture(code, payload={"template": "x" * (128 * 1024), "lab_targets": []})


if __name__ == "__main__":
    unittest.main()
