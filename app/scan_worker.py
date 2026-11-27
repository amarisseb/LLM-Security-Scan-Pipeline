"""Private stdin/stdout scan protocol. Never accepts jobs from argv or files."""
import json
import logging
import os
from pathlib import Path
import sys

from .job_runner import MAX_JOB_BYTES

# Only fixed codes cross IPC; exception text and attributes never do.
_ERROR_CODES = {
    "ApiAuthError": "invalid_api_key",
    "ApplicationAuthError": "application_auth_failed",
    "ApplicationRequestError": "application_request_failed",
    "ChatInputNotFound": "no_chat_found",
    "PageUnavailable": "page_unavailable",
    "AiNotConfirmed": "ai_not_confirmed",
    "ScanTimedOut": "timed_out",
}


def _run(job, progress):
    from . import lab_policy
    payload = job["payload"]
    if not isinstance(payload, dict):
        raise ValueError()
    cap = payload.get("prompt_cap", 10)
    if type(cap) is not int or not 1 <= cap <= 100:
        raise ValueError()
    profile_options = {}
    if "scan_profile" in payload:
        from .run_scan import profile_probes
        profile_probes(payload["scan_profile"])
        profile_options["scan_profile"] = payload["scan_profile"]
    if payload.get("scan_profile", "full") == "free" and payload.get("scenario_sector", "general") != "general":
        raise ValueError("Free scan profile requires general scenarios")
    lab_policy.configure_local_targets(payload.get("lab_targets", []))
    output = Path(job["output_dir"])
    kind = job["kind"]
    if kind == "http":
        # Internal IPC flag, derived by the server from the stored, verified
        # demo identity. Never infer this path from a submitted URL.
        if payload.get("scripted_demo") is True:
            from .demo_scan import run_demo_scan
            return run_demo_scan(output, prompt_cap=1,
                                 scan_profile=payload.get("scan_profile", "full"),
                                 on_progress=progress)
        from .application_scan import run_application_scan
        sector_options = ({"scenario_sector": payload["scenario_sector"]}
                          if "scenario_sector" in payload else {})
        return run_application_scan(payload["url"], payload["template"],
                                    payload["response_path"], payload.get("token", ""),
                                    output, on_progress=progress, prompt_cap=cap,
                                    **sector_options, **profile_options)
    from . import run_scan
    if kind == "api":
        return run_scan.run_api_scan(payload["provider"], payload["model"],
                                     payload["api_key"], output,
                                     prompt_cap=cap, on_progress=progress, **profile_options)
    if kind == "web":
        options = None
        demo = payload.get("demo_target")
        if demo is not None:
            # Internal startup configuration only; exact match, including path.
            lab_policy._parse(demo)
            from . import browser_generator, url_safety
            original = url_safety.validate_target_url

            def validate(url):
                return url_safety.UrlSafetyResult(True) if url == demo else original(url)

            url_safety.validate_target_url = validate
            browser_generator.validate_target_url = validate
            if payload["target_url"] == demo:
                options = {"settle_ms": 1200, "poll_ms": 200, "request_delay_s": 0}
        return run_scan.run_scan(payload["target_url"], output, prompt_cap=cap,
                                 generator_options=options, on_progress=progress,
                                 require_ai_confirmation=not payload.get("skip_ai_check", False),
                                 **profile_options)
    raise ValueError()


def main():
    # Save a protocol descriptor, then suppress Python AND native library output.
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "w", encoding="utf-8")
    with open(os.devnull, "w") as null:
        os.dup2(null.fileno(), 1)
        os.dup2(null.fileno(), 2)
    logging.disable(sys.maxsize)
    # Prevent libraries from creating credential-bearing file handlers.
    class SilentFileHandler(logging.NullHandler):
        def __init__(self, *args, **kwargs):
            super().__init__()

    logging.FileHandler = SilentFileHandler
    logging.basicConfig = lambda *args, **kwargs: None

    def emit(event):
        protocol.write(json.dumps(event, allow_nan=False) + "\n")
        protocol.flush()

    def progress(index, total, probe):
        emit(dict(type="progress", index=index, total=total, probe=str(probe)[:256]))

    try:
        raw = sys.stdin.buffer.readline(MAX_JOB_BYTES + 1)
        if len(raw) > MAX_JOB_BYTES or not raw.endswith(b"\n"):
            raise ValueError()
        job = json.loads(raw)
        if not isinstance(job, dict) or set(job) != {"kind", "scan_id", "payload", "output_dir"}:
            raise ValueError()
        if job["kind"] not in {"web", "api", "http"}:
            raise ValueError()
    except Exception:
        emit(dict(type="error", code="invalid_job"))
        return 1
    try:
        report = _run(job, progress)
        emit(dict(type="result", report_path=str(Path(report).resolve())))
        return 0
    except BaseException as exc:
        code = _ERROR_CODES.get(type(exc).__name__, "scan_failed")
        emit(dict(type="error", code=code))
        return 1
    finally:
        protocol.close()


if __name__ == "__main__":
    sys.exit(main())
