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
import shutil
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

QUEUED, RUNNING, COMPLETE, FAILED = "queued", "running", "complete", "failed"

_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanStore:
    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)
        self._lock = threading.Lock()

    def scan_dir(self, scan_id: str) -> Path | None:
        """The scan's folder, or None if scan_id isn't the shape we generate."""
        if not isinstance(scan_id, str) or not _ID_RE.match(scan_id):
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
        if not status or status["status"] != COMPLETE or not status["report_file"]:
            return None
        return self.scan_dir(scan_id) / status["report_file"]

    def recover_interrupted(self) -> int:
        """After a restart, scans that were queued or running never finished and
        never will: the queue and the browser died with the process."""
        count = 0
        for status in self._all():
            if status["status"] in (QUEUED, RUNNING):
                self.update(status["scan_id"], status=FAILED, error_code="interrupted",
                            finished_at=now_iso())
                count += 1
        return count

    def purge_expired(self, max_age_days: float) -> int:
        """Delete finished scans older than the retention period. Only touches
        folders that hold one of our status files, so anything else sharing
        the directory is left alone."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        count = 0
        for status in self._all():
            if status["status"] not in (COMPLETE, FAILED):
                continue
            if datetime.fromisoformat(status["created_at"]) < cutoff:
                shutil.rmtree(self.scan_dir(status["scan_id"]), ignore_errors=True)
                count += 1
        return count

    # ---- internals ---------------------------------------------------------

    def _all(self) -> list[dict]:
        if not self.root.is_dir():
            return []
        found = []
        with self._lock:
            for child in self.root.iterdir():
                if _ID_RE.match(child.name) and child.is_dir():
                    status = self._read(child)
                    if status:
                        found.append(status)
        return found

    @staticmethod
    def _read(directory: Path | None) -> dict | None:
        try:
            with open(directory / "status.json", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError, TypeError):
            return None

    @staticmethod
    def _write(directory: Path, status: dict) -> None:
        # Write-then-rename so a reader never sees half a file.
        tmp = directory / "status.json.tmp"
        tmp.write_text(json.dumps(status), encoding="utf-8")
        os.replace(tmp, directory / "status.json")
