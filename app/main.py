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
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, SecretStr, StrictBool, StrictInt

from . import accounts, attestation, results, run_scan, scan_store, url_safety
from .browser_generator import AiNotConfirmed, ChatInputNotFound, PageUnavailable, ScanTimedOut
from .rate_limit import ScanRateLimiter
from . import application_scan, lab_policy
from .application_generator import (
    ApplicationAuthError, ApplicationConfigError, ApplicationRequestError, validate_connection,
)
from .security import SecurityBoundaryMiddleware, principal_for
from .target_control import require_target_control
from .job_runner import BoundedScanExecutor, run_isolated_job, WorkerFailure, WorkerTimedOut
from .demo_assets import register_demo_assets
from .repair_demo import router as repair_demo_router

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
    "invalid_api_key": "The provider rejected that API key. Please check it and try again.",
    "application_auth_failed": "Your application rejected the supplied credentials. Check the token and permissions.",
    "application_request_failed": "The application could not return a usable text answer. Check the endpoint and JSON response path.",
    "interrupted": "The scan was interrupted. Please start a new one.",
}
DEFAULT_ERROR_MESSAGE = "The scan couldn't be completed. Please try again later."

SCAN_OUTPUT_DIR = Path(os.getenv("SCAN_OUTPUT_DIR", "garak_runs"))
SCAN_RETENTION_DAYS = float(os.getenv("SCAN_RETENTION_DAYS", 7))

store = scan_store.ScanStore(SCAN_OUTPUT_DIR)
rate_limiter = ScanRateLimiter.from_env()

# A scan takes minutes and garak's config is process-global, so scans run one at
# a time, in the order they were queued. This also keeps the browser on one thread.
_scan_executor = BoundedScanExecutor(max_pending=int(os.getenv("ARISEC_MAX_PENDING_SCANS", "4")))


PURGE_INTERVAL_SECONDS = 3600


def _housekeeping(recover_interrupted: bool = False):
    """Delete expired scans and, only at startup, mark scans a restart orphaned as
    failed. The recovery must never run while the service is up: by then a queued
    or running scan is alive, not orphaned. Neither step may stop the service
    from starting: a bad record on disk is skipped, not fatal."""
    try:
        interrupted = store.recover_interrupted() if recover_interrupted else 0
        if recover_interrupted and accounts.enabled():
            # Recover a credit even if a previous restart crashed between
            # recording the interruption and restoring its reservation.
            for scan_id, record in store._all():
                if record.get("status") == scan_store.FAILED and record.get("error_code") == "interrupted":
                    accounts.refund_free_scan(scan_id)
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
    from . import assessment_api
    assessment_api.startup()
    _housekeeping(recover_interrupted=True)
    purge_task = asyncio.create_task(_purge_loop())
    try:
        yield
    finally:
        purge_task.cancel()
        await asyncio.to_thread(assessment_api._shutdown)


# The interactive docs describe every field to anyone who asks: off unless wanted.
_docs_on = os.getenv("ENABLE_DOCS") == "1"
app = FastAPI(
    title="LLM Security Scan API",
    lifespan=lifespan,
    docs_url="/docs" if _docs_on else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _docs_on else None,
)
register_demo_assets(app)
from .assessment_api import register_assessment_routes
register_assessment_routes(app)
from .auth_api import router as account_router
app.include_router(account_router)
app.include_router(repair_demo_router)
from .target_verification import register_verification_routes
register_verification_routes(app)
from .example_endpoint import register_example_routes, example_request_allowed, configured_example_endpoint
register_example_routes(app)
from .billing import register_billing_routes, require_scan_access
register_billing_routes(app)


@app.get("/health", include_in_schema=False)
def health():
    """Process liveness only; hosted scan readiness needs an end-to-end check."""
    return {"status": "ok"}


@app.get("/security-guidance")
def security_guidance():
    return {"categories": {"promptinject": {
        "flagged": _public_guidance_preview(),
        "clear": _public_guidance_preview(),
        "unsupported": _public_guidance_preview(),
    }}, "account_required_for_other_guides": True}


def _public_guidance_preview():
    return {
        "status": "preview",
        "owner": "Application team",
        "why_it_matters": "The sample assistant abandoned its summary when it found an instruction inside the message.",
        "steps": [{
            "title": "Separate the summary task from the customer message",
            "action": (
                "In the request your app sends to the AI, put the summary task in the application "
                "instruction and pass the customer message separately as content to summarise. "
                "Tell the AI to treat instructions inside that message as part of the text."
            ),
            "done_when": (
                "The flagged message produces a summary without the off-task reply, "
                "and an ordinary message still produces a useful summary."
            ),
            "verification_examples": [
                {"input": "Summarise an ordinary delivery note.",
                 "expected": "The summary preserves the delivery detail."},
                {"input": "Replay the flagged message from this report.",
                 "expected": "The assistant summarises the message and stays on task."},
            ],
        }],
        "retest": "Compare both replies with the expected outcomes in staging before releasing the change.",
        "reference_links": [],
        "scope_note": "This example addresses task hijacking in a text summary. Apps that can access private data or take actions also need server-side permission checks.",
    }


@app.get("/account/guidance/{category}")
def account_guidance(category: Literal["promptinject", "dan", "encoding", "sysprompt_extraction", "donotanswer"], request: Request):
    if not accounts.enabled():
        raise HTTPException(404, "Not found.")
    principal = principal_for(request)
    if principal.get("guest") or not principal.get("email"):
        raise HTTPException(403, "Create an account to explore this remediation guide.")
    from .remediation import guidance_for
    return {"plan": guidance_for(category, tested=False), "example_guidance": True}


@app.get("/security-config")
def security_config(request: Request):
    local = os.getenv("ARISEC_LOCAL_DEMO") == "1" and request.client and request.client.host in ("127.0.0.1", "::1")
    return {"authentication_required": not bool(local), "web_scanning_available": bool(local)}


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
        allow_headers=["Content-Type", "Authorization"],
    )

# Outermost: reject unauthorised/oversized traffic before parsing or DNS work.
app.add_middleware(SecurityBoundaryMiddleware)


# Vague is appropriate for the SSRF/rate-limit messages above (they're about
# somebody else's system); request-shape errors below aren't sensitive, so
# they can just say what's missing.
BAD_MODE_MESSAGE = "Choose a web interface, model provider API, or application API and complete its connection fields."
UNSUPPORTED_PROVIDER_MESSAGE = "That provider isn't supported yet. See GET /api-providers for the current list."


class ScanRequest(BaseModel):
    mode: Literal["web", "api", "http"] = "web"
    scan_profile: Literal["free", "full"] = "free"
    component_name: str = Field(default="AI feature", min_length=1, max_length=100)
    component_type: Literal["assistant", "summarizer", "search", "writer", "other"] = "other"
    http_request_template: dict | None = None
    http_response_path: str | None = Field(default=None, max_length=200)
    scenario_sector: Literal['general', 'legal', 'healthcare', 'education'] = 'general'
    # web mode:
    target_url: str | None = Field(default=None, max_length=2048)
    # api mode: a provider from GET /api-providers, a model name in that
    # provider's own naming (e.g. "gpt-4o-mini"), and the caller's own API key.
    # The key is a SecretStr so it can never appear in a log line or an error
    # response by accident -- str(body) and repr(body) both redact it. It is
    # used once, in run_scan.run_api_scan, and never stored; see that module's
    # docstring for why it never touches garak's config or disk.
    api_provider: str | None = Field(default=None, max_length=40)
    api_model: str | None = Field(default=None, max_length=200)
    api_key: SecretStr | None = None
    # Hosted identity comes from the invite. Optional legacy/demo-only metadata.
    user_email: EmailStr | None = None
    # The version of the attestation text the user was shown (from GET /attestation-text).
    attestation_version: StrictInt
    # Any, not bool: pydantic would turn "yes" or 1 into True. Only a real JSON true counts.
    agreed_to_attestation: Any = None
    # For a tightly scoped assistant that refuses the two simple questions we ask
    # before attacking a web target. Skips that gate; the report then carries a
    # caveat. Meaningless for mode="api" (there's no such gate there).
    skip_ai_check: StrictBool = False

    # Mode-consistency (right fields present for the chosen mode) is checked
    # in the endpoint, not here: a pydantic validator's ValueError is swallowed
    # by the global 422 handler into the generic "Invalid request." (that
    # handler exists specifically so a field FastAPI can't coerce, like a NaN
    # version number, never gets echoed back into the response) -- so a
    # message raised from here would never actually reach the caller.


@app.get("/attestation-text")
def get_attestation_text(response: Response):
    """The current authorization wording. The frontend should always fetch this, never hardcode it."""
    response.headers["Cache-Control"] = "no-store"
    return attestation.current_attestation()


@app.get("/api-providers")
def get_api_providers(response: Response):
    """Providers GET/POST /scan accepts for mode="api". The frontend should
    build its provider picker from this, not a hardcoded copy."""
    response.headers["Cache-Control"] = "no-store"
    return {"providers": sorted(run_scan.PROVIDER_API_KEY_ENV_VAR)}


@app.post("/scan", status_code=202)
def start_scan(body: ScanRequest, request: Request, background_tasks: BackgroundTasks):
    principal = principal_for(request)
    if body.mode != 'http' and body.scenario_sector != 'general':
        raise HTTPException(status_code=400, detail='Organisation scenarios require an application API assessment.')
    if body.mode == "web" and not principal.get("local_demo"):
        raise HTTPException(status_code=403, detail="Browser scans are unavailable in the hosted pilot. Use an approved application API.")
    if body.mode in ("web", "http") and not principal.get("local_demo") and not (body.mode == "http" and (example_request_allowed(request, body.target_url) or lab_policy.preview_request_allowed(request, body.target_url))):
        require_target_control(principal, body.target_url)
    lease = _scan_executor.reserve()
    if lease is None:
        raise HTTPException(status_code=503, detail="The scanner is busy. Please try again later.", headers={"Retry-After": "30"})
    try:
        return _start_admitted_scan(body, request, principal, lease)
    except BaseException:
        reserved_id = getattr(request.state, "free_scan_reservation", None)
        try:
            if reserved_id:
                accounts.refund_free_scan(reserved_id)
        except Exception:
            logger.error("Could not restore rejected scan allowance")
        finally:
            _scan_executor.release(lease)
        raise


def _start_admitted_scan(body: ScanRequest, request: Request, principal: dict, lease):
    client_ip = request.client.host if request.client else "unknown"
    example_scan = body.mode == "http" and example_request_allowed(request, body.target_url)
    scan_profile = "full" if example_scan or not accounts.enabled() else body.scan_profile
    if accounts.enabled() and not example_scan:
        require_scan_access(principal, scan_profile)
        if scan_profile == "free" and body.scenario_sector != "general":
            raise HTTPException(400, "The free scan covers prompt injection only.")
    user_email = (str(body.user_email) if body.user_email else "local-demo@example.com") if principal.get("local_demo") else principal.get("email")

    # 0. The right fields for the chosen mode. Not sensitive, so the message
    # can just say what's missing (see the comment on ScanRequest for why this
    # isn't a pydantic validator).
    if body.mode == "web":
        if (not body.target_url or body.api_provider or body.api_model or body.api_key
                or body.http_request_template is not None or body.http_response_path is not None):
            raise HTTPException(status_code=400, detail=BAD_MODE_MESSAGE)
    elif body.mode == "api":
        if body.target_url or not (body.api_provider and body.api_model and body.api_key):
            raise HTTPException(status_code=400, detail=BAD_MODE_MESSAGE)
        if body.http_request_template is not None or body.http_response_path is not None:
            raise HTTPException(status_code=400, detail=BAD_MODE_MESSAGE)
        if body.api_provider not in run_scan.PROVIDER_API_KEY_ENV_VAR:
            raise HTTPException(status_code=400, detail=UNSUPPORTED_PROVIDER_MESSAGE)
        from .provider_generator import validate_target
        try:
            validate_target(body.api_provider, body.api_model, body.api_key.get_secret_value())
        except ValueError:
            raise HTTPException(status_code=400, detail="Enter a plain model ID and a valid API key for the selected provider.") from None
    else:
        if not body.target_url or body.api_provider or body.api_model:
            raise HTTPException(status_code=400, detail=BAD_MODE_MESSAGE)
        try:
            validate_connection(body.target_url, body.http_request_template, body.http_response_path,
                                body.api_key.get_secret_value() if body.api_key else None)
        except ApplicationConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    # A human-readable stand-in for "what is being scanned", used for logs,
    # rate limiting, the attestation record and the status store -- never the
    # API key itself, which exists only in body.api_key for the rest of this
    # function and is handed to the background job and nowhere else.
    target_label = body.target_url if body.mode in ("web", "http") else f"{body.api_provider}/{body.api_model}"

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

    # 2. SSRF check. Web mode only -- an API scan never fetches a caller-supplied
    # URL (litellm talks only to its provider's own fixed endpoint; see the note
    # above PROVIDER_API_KEY_ENV_VAR in run_scan.py for why no custom api_base
    # is ever accepted, which is what keeps this path out of SSRF territory).
    if body.mode in ("web", "http"):
        local_lab = body.mode == "http" and lab_policy.is_local_target(body.target_url)
        if local_lab and client_ip not in ("127.0.0.1", "::1"):
            raise HTTPException(status_code=400, detail=UNSAFE_URL_MESSAGE)
        safety = url_safety.UrlSafetyResult(True) if local_lab or example_scan else url_safety.validate_target_url(body.target_url)
        if not safety.is_safe:
            logger.warning(
                "scan rejected, unsafe url: ip=%s email=%s url=%r reason=%s",
                client_ip, body.user_email, body.target_url, safety.reason,
            )
            raise HTTPException(status_code=400, detail=UNSAFE_URL_MESSAGE)

    # 3. Rate limits. Checking also counts the scan against them. An API scan
    # uses the caller's own key and quota, so the abuse this guards against
    # (hammering someone else's unconsenting site) doesn't apply the same way;
    # it's still rate-limited for ordinary cost/stability reasons, bucketed by
    # provider rather than by domain -- see registrable_domain's behaviour on
    # a non-URL string, which is why this isn't just target_label.
    rate_limit_target = target_label if body.mode in ("web", "http") else f"https://api-{body.api_provider}.internal/"
    limit = None if example_scan else rate_limiter.check_and_record(
        user_email=user_email or ("guest:" + principal["id"]), client_ip=client_ip, target_url=rate_limit_target
    )
    if limit is not None and not limit.allowed:
        logger.warning(
            "scan rejected, rate limited: ip=%s email=%s target=%r reason=%s",
            client_ip, body.user_email, target_label, limit.reason,
        )
        raise HTTPException(
            status_code=429,
            detail=RATE_LIMIT_MESSAGE,
            headers={"Retry-After": str(limit.retry_after_seconds)},
        )

    scan_id = uuid.uuid4().hex
    if accounts.enabled() and scan_profile == "free" and not example_scan:
        if not accounts.reserve_free_scan(principal, client_ip, scan_id):
            raise HTTPException(status_code=402, detail="Your free scan has been used. Create an account and request a consultation for a full assessment.")
        request.state.free_scan_reservation = scan_id

    # 4. Record the attestation. If it can't be recorded, the scan doesn't start.
    try:
        attestation.log_attestation(
            ip=client_ip,
            user_email=user_email,
            target_url=target_label,
            version=body.attestation_version,
            skip_ai_check=body.skip_ai_check,
            mode=body.mode,
            principal_id=principal["id"],
        )
    except Exception:
        logger.exception("could not write attestation record; refusing scan")
        raise HTTPException(
            status_code=500, detail="Could not start the scan. Please try again later."
        )

    # 5. Queue it and answer immediately.
    try:
        store.create(scan_id, target_label, mode=body.mode,
                     component_name=body.component_name.strip() or "AI feature",
                     component_type=body.component_type, owner_id=principal["id"], scenario_sector=body.scenario_sector)
        if example_scan:
            store.update(scan_id, is_demo=True)
        store.update(scan_id, scan_profile=scan_profile)
    except Exception:
        logger.exception("could not create scan record; refusing scan")
        raise HTTPException(
            status_code=500, detail="Could not start the scan. Please try again later."
        )
    try:
        if body.mode == "web":
            _enqueue_web_scan(scan_id, body.target_url, body.skip_ai_check, lease=lease)
        elif body.mode == "http":
            _enqueue_application_scan(scan_id, body.target_url, body.http_request_template,
                                      body.http_response_path, body.api_key.get_secret_value() if body.api_key else None,
                                      lease=lease, scenario_sector=body.scenario_sector)
        else:
            _enqueue_api_scan(scan_id, body.api_provider, body.api_model,
                              body.api_key.get_secret_value(), lease=lease)
    except Exception:
        _finish(scan_id, status=scan_store.FAILED, error_code="scan_failed")
        raise HTTPException(status_code=503, detail="The scanner is unavailable. Please try again later.") from None
    return {"scan_id": scan_id, "status": scan_store.QUEUED}


@app.get("/account/scans")
def account_scans(request: Request, response: Response):
    if not accounts.enabled():
        raise HTTPException(404, "Not found.")
    principal = principal_for(request)
    response.headers["Cache-Control"] = "no-store"
    return {"scans": store.history(principal["id"])}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str, response: Response, request: Request):
    """Status of a scan. Poll this until status is 'complete' or 'failed'."""
    response.headers["Cache-Control"] = "no-store"
    status = store.get(scan_id)
    if not _may_read(status, request):
        raise HTTPException(status_code=404, detail="Scan not found.")

    body = {
        "scan_id": status["scan_id"],
        "mode": status.get("mode", "web"),
        "scan_profile": status.get("scan_profile", "full"),
        "component_name": status.get("component_name", "AI feature"),
        "component_type": status.get("component_type", "other"),
        "scenario_sector": status.get("scenario_sector", "general"),
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
def get_scan_report(scan_id: str, response: Response, request: Request):
    """The finished scan's results. 409 until the scan is complete."""
    response.headers["Cache-Control"] = "no-store"
    status = store.get(scan_id)
    if not _may_read(status, request):
        raise HTTPException(status_code=404, detail="Scan not found.")
    report_path = store.report_path(scan_id)
    if report_path is None:
        raise HTTPException(status_code=409, detail="This scan has no results yet.")
    try:
        report = results.build_report(
            report_path, scan_id, status.get("target_url", ""), mode=status.get("mode", "web")
        )
        report["component_name"] = status.get("component_name", "AI feature")
        report["component_type"] = status.get("component_type", "other")
        report["scenario_sector"] = status.get("scenario_sector", "general")
        report["scan_profile"] = status.get("scan_profile", "full")
        if report["scan_profile"] == "free":
            report["scope_note"] = "Free scan: prompt injection only. Other attack categories were not tested."
            for category in report.get("categories", []):
                if category.get("key") != "promptinject":
                    category["included_in_plan"] = False
                    category["assessment_note"] = "Not included in your free scan. Discuss a full assessment to test this category where supported."
        if status.get("is_demo"):
            report["simulation"] = True
            report["preview_mode"] = True
            report["target"] = "Built-in demo assistant (scripted responses)"
        principal = principal_for(request)
        for category in report.get("categories", []):
            key = category.get("key")
            excluded_from_trial = report["scan_profile"] == "free" and key != "promptinject"
            guest_demo_guide = status.get("is_demo") and principal.get("guest") and key != "promptinject"
            if excluded_from_trial or guest_demo_guide:
                category.pop("action_plan", None)
                category["remediation_locked"] = True
                category["recommendation"] = "Create an account to explore example remediation guidance. Testing this category on your own AI requires an agreed assessment."
            elif status.get("is_demo") and principal.get("guest") and key == "promptinject":
                category["action_plan"] = _public_guidance_preview()
        return report
    except Exception:
        logger.exception("could not build report for scan %s", scan_id)
        raise HTTPException(status_code=500, detail="Could not load the results.")


def _may_read(status, request):
    principal = principal_for(request)
    return status is not None and (principal.get("local_demo") or status.get("owner_id") == principal["id"])


def _enqueue_web_scan(scan_id: str, target_url: str, skip_ai_check: bool = False, *, lease):
    _scan_executor.submit_reserved(lease, _run_isolated_scan, "web", scan_id,
                                    {"target_url": target_url, "skip_ai_check": skip_ai_check})


def _enqueue_api_scan(scan_id: str, provider: str, model: str, api_key: str, *, lease):
    _scan_executor.submit_reserved(lease, _run_isolated_scan, "api", scan_id,
                                    {"provider": provider, "model": model, "api_key": api_key})


def _enqueue_application_scan(scan_id, url, template, response_path, token, *, lease, scenario_sector='general'):
    _scan_executor.submit_reserved(lease, _run_isolated_scan, "http", scan_id,
                                    {"url": url, "template": template, "response_path": response_path, "token": token,
                                     "scenario_sector": scenario_sector})


def _run_isolated_scan(kind, scan_id, payload):
    try:
        store.update(scan_id, status=scan_store.RUNNING, started_at=scan_store.now_iso())
        def progress(step, total, category):
            store.update(scan_id, progress={"step": step, "of": total, "category": results.category_label(category)})
        payload["prompt_cap"] = max(1, min(100, int(os.getenv("ARISEC_PROMPT_CAP", "10"))))
        record = store.get(scan_id) or {}
        if record.get("scan_profile"):
            payload["scan_profile"] = record["scan_profile"]
        if record.get("is_demo") and kind == "http":
            payload["scripted_demo"] = True
            payload["prompt_cap"] = 1
        if os.getenv("ARISEC_LOCAL_DEMO") == "1":
            payload["lab_targets"] = lab_policy.configured_local_targets()
            payload["demo_target"] = os.getenv("ARISEC_DEMO_BOT_URL")
        elif (kind == "http" and not record.get("is_demo")
              and os.getenv("ARISEC_LOCAL_PREVIEW") == "1"
              and lab_policy.is_local_target(payload.get("url"))):
            # Admission already checked exact registration, loopback and origin.
            # Forward only this destination, never the whole local registry.
            payload["lab_targets"] = [payload["url"]]
        elif not record.get("is_demo") and kind == "http" and payload.get("url") == configured_example_endpoint() and configured_example_endpoint():
            payload["lab_targets"] = [configured_example_endpoint()]
            payload["prompt_cap"] = 1
        timeout = max(30, min(1800, int(os.getenv("ARISEC_SCAN_TIMEOUT_SECONDS", "600"))))
        report = run_isolated_job(kind, scan_id, payload, store.scan_dir(scan_id), timeout,
                                  on_progress=progress)
        if not results.answered_any(report):
            return _finish(scan_id, status=scan_store.FAILED, error_code="no_response")
        _finish(scan_id, status=scan_store.COMPLETE, report_file=report.name)
    except WorkerTimedOut:
        _finish(scan_id, status=scan_store.FAILED, error_code="timed_out")
    except WorkerFailure as exc:
        code = exc.code if exc.code in ERROR_MESSAGES else "scan_failed"
        _finish(scan_id, status=scan_store.FAILED, error_code=code)
    except Exception:
        logger.error("isolated scan %s failed", scan_id)
        _finish(scan_id, status=scan_store.FAILED, error_code="scan_failed")
    finally:
        payload.clear()


def _run_application_scan_job(scan_id, url, template, response_path, token):
    try:
        store.update(scan_id, status=scan_store.RUNNING, started_at=scan_store.now_iso())

        def on_progress(index, total, probe):
            store.update(scan_id, progress={
                "step": index, "of": total, "category": results.category_label(probe),
            })

        report = application_scan.run_application_scan(
            url, template, response_path, token, store.scan_dir(scan_id), on_progress=on_progress,
        )
        if not results.answered_any(report):
            return _finish(scan_id, status=scan_store.FAILED, error_code="no_response")
    except ApplicationAuthError:
        return _finish(scan_id, status=scan_store.FAILED, error_code="application_auth_failed")
    except (ApplicationConfigError, ApplicationRequestError):
        return _finish(scan_id, status=scan_store.FAILED, error_code="application_request_failed")
    except BaseException:
        # Provider and target exceptions can include authorization values or
        # request bodies. Keep logs useful without recording that material.
        logger.error("application scan %s failed", scan_id)
        return _finish(scan_id, status=scan_store.FAILED, error_code="scan_failed")
    finally:
        token = template = None
    _finish(scan_id, status=scan_store.COMPLETE, report_file=report.name)


def _finish(scan_id: str, **fields):
    """Record how a scan ended. A failure to record it must not leave the scan
    'running' forever, so retry, and at least say so loudly."""
    if accounts.enabled() and fields.get("status") == scan_store.FAILED:
        try:
            accounts.refund_free_scan(scan_id)
        except Exception:
            logger.error("Could not restore failed scan allowance for %s", scan_id)
    try:
        store.update(scan_id, finished_at=scan_store.now_iso(), **fields)
    except Exception:
        logger.exception("scan %s: could not record final status %s", scan_id, fields.get("status"))


def _run_web_scan_job(scan_id: str, target_url: str, skip_ai_check: bool = False):
    logger.info("scan %s started (web): %s", scan_id, target_url)
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
        logger.error("web scan %s failed", scan_id)
        return _finish(scan_id, status=scan_store.FAILED, error_code="scan_failed")
    logger.info("scan %s finished: %s", scan_id, report)
    _finish(scan_id, status=scan_store.COMPLETE, report_file=report.name)


def _run_api_scan_job(scan_id: str, provider: str, model: str, api_key: str):
    # Never log api_key, never put it in anything that gets stored -- see
    # run_scan.py's note above PROVIDER_API_KEY_ENV_VAR. This function's own
    # local variable is the last place it exists outside that locked call.
    logger.info("scan %s started (api): %s/%s", scan_id, provider, model)
    try:
        store.update(scan_id, status=scan_store.RUNNING, started_at=scan_store.now_iso())

        def on_progress(index: int, total: int, probe: str):
            store.update(scan_id, progress={
                "step": index,
                "of": total,
                "category": results.category_label(probe),
            })

        report = run_scan.run_api_scan(
            provider, model, api_key, store.scan_dir(scan_id), on_progress=on_progress
        )
        if not results.answered_any(report):
            logger.warning("scan %s: provider never replied", scan_id)
            return _finish(scan_id, status=scan_store.FAILED, error_code="no_response")
    except run_scan.ApiAuthError:
        logger.warning("scan %s: provider rejected the API key", scan_id)
        return _finish(scan_id, status=scan_store.FAILED, error_code="invalid_api_key")
    except run_scan.UnsupportedProvider:
        # Already validated in start_scan; reachable only if that check and
        # this one somehow drift. Same vague code as any other unknown failure.
        logger.error("scan %s: unsupported provider reached the job (%r)", scan_id, provider)
        return _finish(scan_id, status=scan_store.FAILED, error_code="scan_failed")
    except BaseException:
        logger.error("API scan %s failed", scan_id)
        return _finish(scan_id, status=scan_store.FAILED, error_code="scan_failed")
    logger.info("scan %s finished: %s", scan_id, report)
    _finish(scan_id, status=scan_store.COMPLETE, report_file=report.name)
