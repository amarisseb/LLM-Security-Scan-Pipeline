"""Bounded admission and fresh engine globals, not an OS or network sandbox."""
import concurrent.futures
import json
import math
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time

MAX_JOB_BYTES = 256 * 1024
MAX_EVENT_BYTES = 4096
WORKER_ERROR_CODES = frozenset({
    "invalid_job", "scan_failed", "invalid_api_key", "application_auth_failed",
    "application_request_failed", "no_chat_found", "page_unavailable",
    "ai_not_confirmed", "timed_out",
})


def _worker_environment():
    # Explicit names only: never inherit provider credentials, service account
    # configuration, Python injection flags, logging flags, or proxy settings.
    allowed = {
        "SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "SYSTEMDRIVE",
        "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
        "XDG_CACHE_HOME", "HF_HOME", "HF_HUB_CACHE", "TRANSFORMERS_CACHE",
        "TORCH_HOME", "NLTK_DATA", "PLAYWRIGHT_BROWSERS_PATH",
        "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env["PYTHONIOENCODING"] = "utf-8"
    return env


class WorkerFailure(RuntimeError):
    def __init__(self, code="worker_failed"):
        self.code = code
        super().__init__(code)


class WorkerTimedOut(WorkerFailure):
    def __init__(self):
        super().__init__("worker_timeout")


class _Lease:
    def __init__(self, owner):
        self.owner = owner
        self.state = "reserved"

    def release(self):
        return self.owner.release(self)


class BoundedScanExecutor:
    """max_pending counts all reservations, including running jobs.

    Release unused leases explicitly. Submitted leases belong to the future.
    Progress callbacks run on the calling job thread and must return promptly.
    """
    def __init__(self, max_workers=1, max_pending=4):
        if type(max_workers) is not int or max_workers < 1:
            raise ValueError("invalid max_workers")
        if type(max_pending) is not int or max_pending < 1:
            raise ValueError("invalid max_pending")
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self._lock = threading.Lock()
        self._leases = set()
        self._closed = False
        self.max_pending = max_pending

    def reserve(self):
        with self._lock:
            if self._closed or len(self._leases) >= self.max_pending:
                return None
            lease = _Lease(self)
            self._leases.add(lease)
            return lease

    def release(self, lease):
        with self._lock:
            if lease not in self._leases or lease.state != "reserved":
                return False
            self._leases.remove(lease)
            lease.state = "released"
            return True

    def _completed(self, lease):
        with self._lock:
            self._leases.discard(lease)
            lease.state = "released"

    def submit_reserved(self, lease, fn, *args):
        with self._lock:
            if lease not in self._leases or lease.state != "reserved":
                raise ValueError("invalid reservation")
            lease.state = "submitted"
        try:
            future = self._pool.submit(fn, *args)
        except BaseException:
            self._completed(lease)
            raise
        future.add_done_callback(lambda _: self._completed(lease))
        return future

    def shutdown(self, wait=True, *, cancel_futures=False):
        with self._lock:
            self._closed = True
            for lease in list(self._leases):
                if lease.state == "reserved":
                    self._leases.remove(lease)
                    lease.state = "released"
        self._pool.shutdown(wait=wait, cancel_futures=cancel_futures)


def _worker_command():
    # Private seam for real subprocess fixtures, never supplied by an API job.
    return [sys.executable, "-m", "app.scan_worker"]


def _kill_tree(process, job=None):
    if job is not None:
        job.terminate_and_wait(timeout=5)
    elif os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)


def run_isolated_job(kind, scan_id, payload, output_dir, timeout_seconds,
                     on_progress=None):
    """Run one bounded stdin job. Internal payload: lab_targets/demo_target.

    on_progress receives (step, total, category).
    Credentials must only be in payload; no job data enters argv or environment.
    """
    if not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("invalid timeout")
    root = Path(output_dir).resolve()
    try:
        data = json.dumps(dict(kind=kind, scan_id=scan_id, payload=payload,
                               output_dir=str(root)), allow_nan=False).encode() + b"\n"
    except (TypeError, ValueError):
        raise WorkerFailure("invalid_job") from None
    if len(data) > MAX_JOB_BYTES:
        raise WorkerFailure("invalid_job")
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(_worker_command(), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   cwd=str(Path(__file__).resolve().parent.parent),
                                   env=_worker_environment(),
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                                   start_new_session=os.name != "nt")
    except OSError:
        raise WorkerFailure("worker_start_failed") from None
    job = None
    if os.name == "nt":
        try:
            from app.windows_job import WindowsJob
            job = WindowsJob()
            # No stdin is written until containment succeeds. The worker waits
            # for its job on stdin before it can create any descendants.
            job.assign(process)
        except OSError:
            try:
                _kill_tree(process)
            finally:
                if job is not None:
                    job.close()
                process.stdin.close()
                process.stdout.close()
            raise WorkerFailure("worker_start_failed") from None
    events = queue.Queue(maxsize=32)
    stop = threading.Event()

    def publish(item):
        while not stop.is_set():
            try:
                events.put(item, timeout=.05)
                return
            except queue.Full:
                pass

    def read():
        try:
            while not stop.is_set():
                line = process.stdout.readline(MAX_EVENT_BYTES + 1)
                if not line:
                    publish(None)
                    return
                if len(line) > MAX_EVENT_BYTES or not line.endswith(b"\n"):
                    publish(False)
                    return
                publish(line)
        except (OSError, ValueError):
            publish(False)

    def write():
        try:
            process.stdin.write(data)
            process.stdin.close()
        except (OSError, ValueError):
            publish(False)

    reader = threading.Thread(target=read, daemon=True)
    writer = threading.Thread(target=write, daemon=True)
    reader.start()
    writer.start()
    result = None
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WorkerTimedOut()
            try:
                line = events.get(timeout=min(.1, remaining))
            except queue.Empty:
                continue
            if line is None:
                break
            if line is False or result is not None:
                raise WorkerFailure("worker_protocol")
            try:
                event = json.loads(line)
                event_type = event["type"]
                if event_type == "progress":
                    if (set(event) != {"type", "index", "total", "probe"}
                            or type(event["index"]) is not int
                            or type(event["total"]) is not int
                            or not 1 <= event["index"] <= event["total"] <= 10000
                            or not isinstance(event["probe"], str)
                            or len(event["probe"]) > 256):
                        raise ValueError()
                elif event_type == "error":
                    code = event.get("code")
                    if set(event) != {"type", "code"} or code not in WORKER_ERROR_CODES:
                        raise ValueError()
                    raise WorkerFailure(code)
                elif event_type == "result":
                    if set(event) != {"type", "report_path"} or not isinstance(event["report_path"], str):
                        raise ValueError()
                    result = Path(event["report_path"]).resolve()
                    if not result.is_relative_to(root) or not result.name.endswith(".report.jsonl") or not result.is_file():
                        raise ValueError()
                else:
                    raise ValueError()
            except (ValueError, TypeError, KeyError, OSError):
                raise WorkerFailure("worker_protocol") from None
            if event_type == "progress" and on_progress:
                on_progress(event["index"], event["total"], event["probe"])
        try:
            status = process.wait(timeout=max(.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise WorkerTimedOut() from None
        if status != 0 or result is None:
            raise WorkerFailure("worker_failed")
        return result
    finally:
        stop.set()
        try:
            _kill_tree(process, job)
        finally:
            if job is not None:
                job.close()
        reader.join(timeout=1)
        writer.join(timeout=1)
        if not reader.is_alive():
            process.stdout.close()
        if not writer.is_alive():
            process.stdin.close()
