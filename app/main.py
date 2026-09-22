"""HTTP API for starting scans.

Run from the repo root:  uvicorn app.main:app

Behind a reverse proxy, start uvicorn with --proxy-headers and
--forwarded-allow-ips=<proxy address> so request.client is the real caller.
The IP goes into the attestation log and the rate limiter, so it must not be
taken from a header the caller can set.
"""

import asyncio
import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, StrictBool, StrictInt

from . import attestation, results, run_scan, scan_store, url_safety
from .browser_generator import AiNotConfirmed, ChatInputNotFound, PageUnavailable, ScanTimedOut
from .rate_limit import ScanRateLimiter

logger = logging.getLogger("app.api")

# Deliberately vague. The specific reason (private IP, blocked port, unresolvable
# name...) goes to our logs, never to the caller: it would be a map of what to
# try next. The same goes for which rate limit was hit.
UNSAFE_URL_MESSAGE = (
    "This URL can't be scanned. Make sure it is a publicly reachable website "
    "that you are authorized to test."
)
RATE_LIMIT_MESSAGE = "Scan limit reached. Please try again later."

# What the caller is told when a scan fails, by error code. Only the codes that
# are safe to explain get a specific message; anything else (including a scan
# aborted for touching a non-public address) is just "couldn't complete".
ERROR_MESSAGES = {
    "no_chat_found": (
        "We couldn't find a chat box or input field on that page. This scanner works "
        "with public chat widgets and one-shot 'generate' pages."
    ),
    "no_response": (
        "We sent messages to that page but it never replied, so there is nothing to report. "
        "It may not be an AI chat, or it may need a login."
    ),
    "page_unavailable": "That page returned an error, so there was nothing to scan.",
    "ai_not_confirmed": (
        "We couldn't confirm this page is powered by an AI model: it didn't answer two "
        "simple questions. We stopped before sending any attack messages, so we don't "
        "flood a login form, contact form or search box. If it's a tightly scoped "
        "assistant that refuses off-topic questions, you can run the scan anyway."
    ),
    "timed_out": "The scan took too long and was stopped. Please try again later.",
    "interrupted": "The scan was interrupted. Please start a new one.",
}
DEFAULT_ERROR_MESSAGE = "The scan couldn't be completed. Please try again later."

SCAN_OUTPUT_DIR = Path(os.getenv("SCAN_OUTPUT_DIR", "garak_runs"))
SCAN_RETENTION_DAYS = float(os.getenv("SCAN_RETENTION_DAYS", 7))

store = scan_store.ScanStore(SCAN_OUTPUT_DIR)
rate_limiter = ScanRateLimiter.from_env()

# A scan takes minutes and garak's config is process-global, so scans run one at
# a time, in the order they were queued. This also keeps the browser on one thread.
_scan_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="scan")


PURGE_INTERVAL_SECONDS = 3600


def _housekeeping(recover_interrupted: bool = False):
    """Delete expired scans and, only at startup, mark scans a restart orphaned as
    failed. The recovery must never run while the service is up: by then a queued
    or running scan is alive, not orphaned. Neither step may stop the service
    from starting: a bad record on disk is skipped, not fatal."""
    try:
        interrupted = store.recover_interrupted() if recover_interrupted else 0
        purged = store.purge_expired(SCAN_RETENTION_DAYS)
        if interrupted or purged:
            logger.info("housekeeping: %d interrupted scans marked failed, %d expired scans deleted",
                        interrupted, purged)
    except Exception:
        logger.exception("housekeeping failed; continuing")


async def _purge_loop():
    while True:
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)
        await asyncio.get_running_loop().run_in_executor(None, _housekeeping)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _housekeeping(recover_interrupted=True)
    purge_task = asyncio.create_task(_purge_loop())
    try:
        yield
    finally:
        purge_task.cancel()


# The interactive docs describe every field to anyone who asks: off unless wanted.
_docs_on = os.getenv("ENABLE_DOCS") == "1"
app = FastAPI(
    title="LLM Security Scan API",
    lifespan=lifespan,
    docs_url="/docs" if _docs_on else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _docs_on else None,
)


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError):
    # A fixed body. FastAPI's default echoes the offending input back, and
    # crashes (500) when that input is NaN or a lone surrogate.
    return JSONResponse(status_code=422, content={"detail": "Invalid request."})


# The frontend lives on another origin, so the browser blocks its calls unless
# that origin is allowed. Nothing is allowed until configured.
_cors_origins = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "").split(",") if o.strip()]
_cors_regex = os.getenv("CORS_ALLOW_ORIGIN_REGEX") or None
if _cors_origins or _cors_regex:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_origin_regex=_cors_regex,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )


class ScanRequest(BaseModel):
    target_url: str = Field(max_length=2048)
    user_email: EmailStr
    # The version of the attestation text the user was shown (from GET /attestation-text).
    attestation_version: StrictInt
    # Any, not bool: pydantic would turn "yes" or 1 into True. Only a real JSON true counts.
    agreed_to_attestation: Any = None
    # For a tightly scoped assistant that refuses the two simple questions we ask
    # before attacking. Skips that gate; the report then carries a caveat.
    skip_ai_check: StrictBool = False


@app.get("/attestation-text")
def get_attestation_text(response: Response):
    """The current authorization wording. The frontend should always fetch this, never hardcode it."""
    response.headers["Cache-Control"] = "no-store"
    return attestation.current_attestation()


@app.post("/scan", status_code=202)
def start_scan(body: ScanRequest, request: Request, background_tasks: BackgroundTasks):
    client_ip = request.client.host if request.client else "unknown"

    # 1. Explicit attestation, of the wording currently in force.
    if body.agreed_to_attestation is not True:
        raise HTTPException(
            status_code=400,
            detail="You must confirm you are authorized to scan this target.",
        )
    if body.attestation_version != attestation.CURRENT_ATTESTATION_VERSION:
        # The user agreed to text that has since changed (a stale page). What we
        # log must be what they saw, so make them look again.
        raise HTTPException(
            status_code=409,
            detail="The authorization statement has been updated. Please review it and agree again.",
        )

    # 2. SSRF check. Nothing touches the URL before this passes.
    safety = url_safety.validate_target_url(body.target_url)
    if not safety.is_safe:
        logger.warning(
            "scan rejected, unsafe url: ip=%s email=%s url=%r reason=%s",
            client_ip, body.user_email, body.target_url, safety.reason,
        )
        raise HTTPException(status_code=400, detail=UNSAFE_URL_MESSAGE)

    # 3. Rate limits. Checking also counts the scan against them.
    limit = rate_limiter.check_and_record(
        user_email=body.user_email, client_ip=client_ip, target_url=body.target_url
    )
    if not limit.allowed:
        logger.warning(
            "scan rejected, rate limited: ip=%s email=%s url=%r reason=%s",
            client_ip, body.user_email, body.target_url, limit.reason,
        )
        raise HTTPException(
            status_code=429,
            detail=RATE_LIMIT_MESSAGE,
            headers={"Retry-After": str(limit.retry_after_seconds)},
        )

    # 4. Record the attestation. If it can't be recorded, the scan doesn't start.
    try:
        attestation.log_attestation(
            ip=client_ip,
            user_email=body.user_email,
            target_url=body.target_url,
            version=body.attestation_version,
            skip_ai_check=body.skip_ai_check,
        )
    except Exception:
        logger.exception("could not write attestation record; refusing scan")
        raise HTTPException(
            status_code=500, detail="Could not start the scan. Please try again later."
        )

    # 5. Queue it and answer immediately.
    scan_id = uuid.uuid4().hex
    try:
        store.create(scan_id, body.target_url)
    except Exception:
        logger.exception("could not create scan record; refusing scan")
        raise HTTPException(
            status_code=500, detail="Could not start the scan. Please try again later."
        )
    background_tasks.add_task(_enqueue_scan, scan_id, body.target_url, body.skip_ai_check)
    return {"scan_id": scan_id, "status": scan_store.QUEUED}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str, response: Response):
    """Status of a scan. Poll this until status is 'complete' or 'failed'."""
    response.headers["Cache-Control"] = "no-store"
    status = store.get(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    body = {
        "scan_id": status["scan_id"],
        "status": status["status"],
        "created_at": status["created_at"],
        "started_at": status.get("started_at"),
        "finished_at": status.get("finished_at"),
        "progress": status.get("progress"),
        "error": None,
    }
    if status["status"] == scan_store.FAILED:
        code = status.get("error_code") or "scan_failed"
        body["error"] = {"code": code, "message": ERROR_MESSAGES.get(code, DEFAULT_ERROR_MESSAGE)}
    return body


@app.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: str, response: Response):
    """The finished scan's results. 409 until the scan is complete."""
    response.headers["Cache-Control"] = "no-store"
    status = store.get(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    report_path = store.report_path(scan_id)
    if report_path is None:
        raise HTTPException(status_code=409, detail="This scan has no results yet.")
    try:
        return results.build_report(report_path, scan_id, status.get("target_url", ""))
    except Exception:
        logger.exception("could not build report for scan %s", scan_id)
        raise HTTPException(status_code=500, detail="Could not load the results.")


def _enqueue_scan(scan_id: str, target_url: str, skip_ai_check: bool = False):
    future = _scan_executor.submit(_run_scan_job, scan_id, target_url, skip_ai_check)
    # _run_scan_job handles its own errors; this catches anything it couldn't.
    future.add_done_callback(
        lambda f: f.exception() and logger.error("scan job crashed: %r", f.exception())
    )


def _finish(scan_id: str, **fields):
    """Record how a scan ended. A failure to record it must not leave the scan
    'running' forever, so retry, and at least say so loudly."""
    try:
        store.update(scan_id, finished_at=scan_store.now_iso(), **fields)
    except Exception:
        logger.exception("scan %s: could not record final status %s", scan_id, fields.get("status"))


def _run_scan_job(scan_id: str, target_url: str, skip_ai_check: bool = False):
    logger.info("scan %s started: %s", scan_id, target_url)
    try:
        store.update(scan_id, status=scan_store.RUNNING, started_at=scan_store.now_iso())

        def on_progress(index: int, total: int, probe: str):
            store.update(scan_id, progress={
                "step": index,
                "of": total,
                "category": results.category_label(probe),
            })

        report = run_scan.run_scan(
            target_url, store.scan_dir(scan_id), on_progress=on_progress,
            require_ai_confirmation=not skip_ai_check,
        )
        # A page that took our messages but never answered would otherwise
        # produce a report reading "0% exposed": a false all-clear.
        if not results.answered_any(report):
            logger.warning("scan %s: target never replied", scan_id)
            return _finish(scan_id, status=scan_store.FAILED, error_code="no_response")
    except ChatInputNotFound:
        logger.warning("scan %s: no chat input found on target", scan_id)
        return _finish(scan_id, status=scan_store.FAILED, error_code="no_chat_found")
    except PageUnavailable:
        logger.warning("scan %s: target returned an HTTP error", scan_id)
        return _finish(scan_id, status=scan_store.FAILED, error_code="page_unavailable")
    except AiNotConfirmed:
        logger.warning("scan %s: target did not answer like an AI; nothing was attacked", scan_id)
        return _finish(scan_id, status=scan_store.FAILED, error_code="ai_not_confirmed")
    except ScanTimedOut:
        logger.error("scan %s: exceeded the scan time limit", scan_id)
        return _finish(scan_id, status=scan_store.FAILED, error_code="timed_out")
    except BaseException:
        logger.exception("scan %s failed", scan_id)
        return _finish(scan_id, status=scan_store.FAILED, error_code="scan_failed")
    logger.info("scan %s finished: %s", scan_id, report)
    _finish(scan_id, status=scan_store.COMPLETE, report_file=report.name)
