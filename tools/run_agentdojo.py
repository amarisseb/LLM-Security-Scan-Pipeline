"""Supervise the optional AgentDojo worker; never imports it into the web app."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.agentdojo_support import local_endpoint


def main():
    parser = argparse.ArgumentParser(description="Run one local AgentDojo case with clean and capability controls.")
    parser.add_argument("--check", action="store_true", help="Check the pinned environment and task definitions; no model calls")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434/v1")
    parser.add_argument("--model", help="Exact model name served by your local OpenAI-compatible server")
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--focused", action="store_true", help="Use only calendar search and simulated email tools")
    args = parser.parse_args()
    try:
        local_endpoint(args.endpoint)
        if not 10 <= args.seconds <= 600:
            raise ValueError("Use a wall-time budget between 10 and 600 seconds")
        if not args.check and (not args.model or len(args.model) > 160 or any(ord(c) < 32 for c in args.model)):
            raise ValueError("An exact local model name is required")
    except ValueError as exc:
        parser.error(str(exc))
    python = ROOT / ".venv" / "assurance-agentdojo" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        parser.error("Install the optional environment using integrations/agentdojo/requirements.txt first")
    run_id = uuid4().hex
    output = ROOT / ".arisec-private" / "assurance" / run_id
    output.mkdir(parents=True, exist_ok=False)
    config = {"run_id": run_id, "endpoint": args.endpoint, "model": args.model,
              "seconds": args.seconds, "check": args.check, "focused": args.focused,
              "progress_id": os.environ.get("ARISEC_ASSURANCE_RUN_ID")}
    # No inherited provider credentials, proxy variables, user site packages or
    # tracing configuration. Worker is fixed code and never starts subprocesses.
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH"}}
    env.update(PYTHONNOUSERSITE="1", PYTHON_DOTENV_DISABLED="1", HF_HUB_OFFLINE="1",
               LANGCHAIN_TRACING_V2="false", LANGSMITH_TRACING="false", OTEL_SDK_DISABLED="true")
    summary = output / "summary.json"
    process = subprocess.Popen([str(python), str(ROOT / "integrations/agentdojo/worker.py")],
                               stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, cwd=output, env=env)
    try:
        process.communicate(json.dumps(config).encode(), timeout=args.seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        summary.write_text(json.dumps({"schema": "arisec.agentdojo.v1", "run_id": run_id,
                                      "status": "inconclusive", "error_code": "worker_timeout",
                                      "customer_system_tested": False}), encoding="utf-8")
    if not summary.is_file():
        summary.write_text(json.dumps({"schema": "arisec.agentdojo.v1", "run_id": run_id,
                                      "status": "inconclusive", "error_code": "worker_failed",
                                      "customer_system_tested": False}), encoding="utf-8")
    result = json.loads(summary.read_text(encoding="utf-8"))
    print(json.dumps({"status": result["status"], "summary": str(summary),
                      "checked_at": datetime.now(timezone.utc).isoformat(),
                      "assessment": result.get("assessment"), "error_code": result.get("error_code")}, indent=2))
    return 0 if result["status"] in {"complete", "environment_ready"} else 1


if __name__ == "__main__":
    sys.exit(main())
