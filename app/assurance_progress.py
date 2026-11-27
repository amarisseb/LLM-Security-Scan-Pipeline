"""Small, fixed-schema progress messages for the owned local benchmark."""
import json
from pathlib import Path
import re
import time

DIRECTORY = Path(__file__).resolve().parents[1] / ".arisec-private/assurance-progress"
STAGES = ("preparing_model", "model_ready", "clean_user", "goal_capability", "attacked", "finishing")


def publish(run_id, stage, *, completed=(), requests=0, tools=0):
    if not run_id:
        return
    if not re.fullmatch(r"[0-9a-f]{32}", run_id) or stage not in STAGES:
        raise ValueError("Invalid progress identity")
    path = DIRECTORY / (run_id + ".json")
    temporary = path.with_suffix(".tmp")
    try:
        DIRECTORY.mkdir(parents=True, exist_ok=True)
        temporary.write_text(json.dumps({"stage": stage, "completed": list(completed),
                                         "requests": requests, "tools": tools, "updated_at": time.time()}), encoding="utf-8")
        temporary.replace(path)
    except OSError:
        # A short-lived Windows reader can deny replacement. Observability
        # must not abort the actual test; the next update retries publication.
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def read(run_id):
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        return None
    try:
        path = DIRECTORY / (run_id + ".json")
        if path.stat().st_size > 8192:
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("stage") not in STAGES:
            return None
        return {"stage": raw["stage"], "completed": [name for name in ("clean_user", "goal_capability", "attacked")
                    if name in raw.get("completed", [])],
                "requests": raw.get("requests") if type(raw.get("requests")) is int and 0 <= raw["requests"] <= 30 else 0,
                "tools": raw.get("tools") if type(raw.get("tools")) is int and 0 <= raw["tools"] <= 60 else 0}
    except (OSError, ValueError, TypeError, AttributeError):
        return None
