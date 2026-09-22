"""Where a scan's status lives: a small status.json in the scan's own folder.

    <root>/<scan_id>/status.json
    <root>/<scan_id>/garak.<run_id>.report.jsonl   (written by garak)

On disk rather than in memory so a restart doesn't make every scan vanish. The
scan_id is the only thing that grants access to a result, so it is 128 random
bits, and every lookup validates its shape before it becomes a path.
"""

import json
import os
import re
import logging
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

QUEUED, RUNNING, COMPLETE, FAILED = "queued", "running", "complete", "failed"

logger = logging.getLogger(__name__)

_ID_RE = re.compile(r"[0-9a-f]{32}")  # used with fullmatch: "$" would also accept a trailing newline

_REQUIRED_FIELDS = ("scan_id", "status", "created_at")
_MAX_STATUS_BYTES = 1_000_000  # ours are under 1 KB


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanStore:
    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)
        self._lock = threading.Lock()

    def scan_dir(self, scan_id: str) -> Path | None:
        """The scan's folder, or None if scan_id isn't the shape we generate."""
        if not isinstance(scan_id, str) or not _ID_RE.fullmatch(scan_id):
            return None
        return self.root / scan_id

    def create(self, scan_id: str, target_url: str) -> None:
        directory = self.scan_dir(scan_id)
        with self._lock:
            directory.mkdir(parents=True, exist_ok=True)
            self._write(directory, {
                "scan_id": scan_id,
                "status": QUEUED,
                "target_url": target_url,
                "created_at": now_iso(),
                "started_at": None,
                "finished_at": None,
                "progress": None,
                "error_code": None,
                "report_file": None,
            })

    def update(self, scan_id: str, **fields) -> None:
        directory = self.scan_dir(scan_id)
        with self._lock:
            status = self._read(directory)
            if status is None:
                return
            status.update(fields)
            self._write(directory, status)

    def get(self, scan_id: str) -> dict | None:
        directory = self.scan_dir(scan_id)
        if directory is None:
            return None
        with self._lock:
            return self._read(directory)

    def report_path(self, scan_id: str) -> Path | None:
        status = self.get(scan_id)
        if not status or status["status"] != COMPLETE or not status.get("report_file"):
            return None
        return self.scan_dir(scan_id) / status["report_file"]

    def recover_interrupted(self) -> int:
        """After a restart, scans that were queued or running never finished and
        never will: the queue and the browser died with the process."""
        count = 0
        for scan_id, status in self._all():
            if status["status"] in (QUEUED, RUNNING):
                self.update(scan_id, status=FAILED, error_code="interrupted",
                            finished_at=now_iso())
                count += 1
        return count

    def purge_expired(self, max_age_days: float) -> int:
        """Delete finished scans older than the retention period. Only touches
        folders that hold one of our status files, so anything else sharing
        the directory is left alone. Deletion is by folder name, never by an id
        read out of the file."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        count = 0
        for scan_id, status in self._all():
            if status["status"] not in (COMPLETE, FAILED):
                continue
            if self._created(status) < cutoff:
                shutil.rmtree(self.root / scan_id, ignore_errors=True)
                count += 1
        return count

    # ---- internals ---------------------------------------------------------

    @staticmethod
    def _created(status: dict) -> datetime:
        created = datetime.fromisoformat(status["created_at"])
        return created if created.tzinfo else created.replace(tzinfo=timezone.utc)

    def _all(self) -> list[tuple[str, dict]]:
        """(scan_id from the folder name, status) for every readable, well-formed
        record. A corrupt or foreign status.json is logged and skipped: one bad
        file must not stop the service starting or block a sweep of the rest."""
        if not self.root.is_dir():
            return []
        found = []
        with self._lock:
            for child in self.root.iterdir():
                if not (_ID_RE.fullmatch(child.name) and child.is_dir()):
                    continue
                status = self._read(child)
                if status is None:
                    continue
                try:
                    if not isinstance(status, dict) or any(k not in status for k in _REQUIRED_FIELDS):
                        raise ValueError("missing fields")
                    self._created(status)  # must parse
                except (ValueError, TypeError):
                    logger.warning("skipping malformed status file in %s", child.name)
                    continue
                found.append((child.name, status))
        return found

    @staticmethod
    def _read(directory: Path | None) -> dict | None:
        try:
            path = directory / "status.json"
            if path.stat().st_size > _MAX_STATUS_BYTES:
                return None
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError, TypeError, RecursionError, MemoryError):
            # RecursionError: a file of 300,000 "[" is valid to start parsing and
            # then overflows the parser. One poison file must not abort a sweep.
            return None
        # Valid JSON isn't necessarily one of our records ("123", a list, a dict
        # from something else). Callers index into this, so only hand back a dict.
        if not isinstance(data, dict) or any(k not in data for k in _REQUIRED_FIELDS):
            return None
        return data

    @staticmethod
    def _write(directory: Path, status: dict) -> None:
        # Write-then-rename so a reader never sees half a file. On Windows the
        # rename fails with PermissionError while anything else (antivirus, a
        # backup agent, a monitor) has the file open, so retry briefly.
        tmp = directory / "status.json.tmp"
        tmp.write_text(json.dumps(status), encoding="utf-8")
        for attempt in range(8):
            try:
                os.replace(tmp, directory / "status.json")
                return
            except PermissionError:
                if attempt == 7:
                    raise
                time.sleep(0.05 * 2 ** attempt)
