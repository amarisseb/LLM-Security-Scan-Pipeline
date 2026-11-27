"""Server-side scan entitlements and stored consultation requests.

Main must call require_scan_access(principal_for(request), scan_profile) before
queueing, only when self-service is enabled. Legacy/demo bypass belongs in Main.
Free profiles still require the one-scan principal/network credit check, INCLUDING
registered free accounts: signup is neither a credit reset nor a paid grant.
This module does not consume credits or replace the existing hourly/daily limits.

register_billing_routes(app) adds GET /plans, GET /account/plan and registered-only
POST/GET /account/consultation. Mount
SecurityBoundaryMiddleware outermost; /account/plan requires its session state.
grant_subscription(id, plan, expires_at) is operator-only Python API, never HTTP.
expires_at is a finite positive Unix timestamp in seconds (no perpetual grants).
Pricing is quoted after consultation. Requests are stored for operator review;
no email notification, checkout, webhook or payment-provider SDK is configured.
"""

import asyncio
import math
import secrets
import sqlite3
import time
from contextlib import closing

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.responses import JSONResponse

from . import accounts
from .security import principal_for

_CATEGORIES = ("promptinject", "dan", "encoding", "sysprompt_extraction", "donotanswer")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS subscriptions (
 principal_id TEXT PRIMARY KEY REFERENCES accounts(id),
 plan TEXT NOT NULL CHECK(plan IN ('full','team')),
 status TEXT NOT NULL DEFAULT 'active',
 expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS consultations (
 id TEXT PRIMARY KEY,
 principal_id TEXT NOT NULL REFERENCES accounts(id),
 email_snapshot TEXT NOT NULL,
 message TEXT NOT NULL,
 created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS consultation_principal_time
 ON consultations(principal_id, created_at DESC);
"""


def _initialize(db):
    db.executescript(_SCHEMA)


def effective_plan(principal) -> str:
    """Read current durable entitlement, never a request's plan/status claims."""
    if not isinstance(principal, dict) or principal.get("guest") or not isinstance(principal.get("id"), str):
        return "free"
    try:
        with closing(accounts.connect_db()) as db:
            _initialize(db)
            row = db.execute(
                "SELECT s.plan,s.status,s.expires_at FROM subscriptions s "
                "JOIN accounts a ON a.id=s.principal_id WHERE s.principal_id=? AND a.email IS NOT NULL",
                (principal["id"],),
            ).fetchone()
            if row and row["status"] == "active" and row["plan"] in ("full", "team"):
                expiry = row["expires_at"]
                if isinstance(expiry, (int, float)) and math.isfinite(expiry) and expiry > time.time():
                    return row["plan"]
            return "free"
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "Plan information is unavailable.") from None


def require_scan_access(principal, scan_profile) -> None:
    """Validate profile, then require an active paid entitlement for full scans.

    Free access here is profile permission, NOT approval to consume a free scan.
    Main must separately enforce the remaining one-scan principal/network credit.
    """
    if not isinstance(scan_profile, str) or scan_profile not in ("free", "full"):
        raise HTTPException(400, "Invalid scan profile.")
    if scan_profile == "full" and effective_plan(principal) not in ("full", "team"):
        raise HTTPException(402, "An active paid plan is required for a full scan.")


def grant_subscription(principal_id, plan, expires_at):
    """Operator-only durable upsert; only registered accounts may receive grants."""
    if not isinstance(principal_id, str) or not principal_id or plan not in ("full", "team"):
        raise ValueError("Invalid subscription")
    if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)) or not math.isfinite(expires_at) or expires_at <= 0:
        raise ValueError("Invalid subscription expiry")
    with closing(accounts.connect_db()) as db, db:
        _initialize(db)
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT email FROM accounts WHERE id=?", (principal_id,)).fetchone()
        if row is None or row["email"] is None:
            raise ValueError("A registered account is required")
        db.execute(
            "INSERT INTO subscriptions(principal_id,plan,status,expires_at) VALUES (?,?,'active',?) "
            "ON CONFLICT(principal_id) DO UPDATE SET plan=excluded.plan,status='active',expires_at=excluded.expires_at",
            (principal_id, plan, expires_at),
        )


def catalog() -> dict:
    """Return isolated public tier metadata; unknown prices are not zero prices."""
    return {
        "billing_enabled": False,
        "plans": [
            {"id": "free", "name": "Free", "price": 0, "scan_profile": "free", "categories": ["promptinject"],
             "coverage": "One free prompt-injection scan of your own AI, subject to principal and network credit. The configured scripted example can be repeated without using that allowance."},
            {"id": "full", "name": "Full assessment", "price": None, "price_label": "Quoted after consultation", "cta": "Discuss assessment", "scan_profile": "full", "categories": list(_CATEGORIES),
             "coverage": "The five currently configured categories; assessment support depends on the scan mode."},
            {"id": "team", "name": "Bespoke", "price": None, "price_label": "Quoted after consultation", "cta": "Discuss assessment", "scan_profile": "full", "categories": list(_CATEGORIES),
             "coverage": "Discuss assessment scope based on the five currently configured categories; additional work requires agreement."},
        ],
        "scope_note": "Coverage is limited to these configured categories, not all garak probes. Results are not a compliance audit or a guarantee of security.",
        "consultation_note": "Request an assessment discussion. Your request is stored for operator review; sending it does not grant paid scan access.",
    }


class ConsultationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(default="", max_length=2000, strict=True)


def _registered_principal(request):
    if not accounts.enabled():
        raise HTTPException(404, "Not found.")
    principal = principal_for(request)
    if not getattr(request.state, "account_boundary", False):
        raise HTTPException(403, "Request denied.")
    if principal.get("guest"):
        raise HTTPException(403, "Create an account to request a consultation.")
    return principal


def _request_consultation(principal, message):
    now = time.time()
    try:
        with closing(accounts.connect_db()) as db, db:
            _initialize(db)
            db.execute("BEGIN IMMEDIATE")
            member = db.execute("SELECT email FROM accounts WHERE id=? AND email IS NOT NULL", (principal["id"],)).fetchone()
            if member is None:
                raise HTTPException(403, "A registered account is required.")
            if db.execute("SELECT 1 FROM consultations WHERE principal_id=? AND created_at>? LIMIT 1", (principal["id"], now - 86400)).fetchone():
                raise HTTPException(429, "A consultation has already been requested. Please try again later.")
            request_id = secrets.token_hex(16)
            db.execute("INSERT INTO consultations VALUES (?,?,?,?,?)", (request_id, principal["id"], member["email"], message, now))
            return {"request_id": request_id, "status": "requested"}
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "Consultation storage is unavailable.") from None


def _latest_consultation(principal):
    try:
        with closing(accounts.connect_db()) as db:
            _initialize(db)
            if db.execute("SELECT 1 FROM accounts WHERE id=? AND email IS NOT NULL", (principal["id"],)).fetchone() is None:
                raise HTTPException(403, "A registered account is required.")
            row = db.execute("SELECT id FROM consultations WHERE principal_id=? ORDER BY created_at DESC,id DESC LIMIT 1", (principal["id"],)).fetchone()
            return {"request_id": row["id"] if row else None, "status": "requested" if row else "not_requested"}
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "Consultation storage is unavailable.") from None


def register_billing_routes(app):
    """Register metadata and protected consultation routes, never checkout."""
    @app.get("/plans", include_in_schema=False)
    def plans():
        return catalog()

    @app.get("/account/plan", include_in_schema=False)
    def account_plan(request: Request):
        if not accounts.enabled():
            raise HTTPException(404, "Not found.")
        principal = principal_for(request)
        if not getattr(request.state, "account_boundary", False):
            raise HTTPException(403, "Request denied.")
        plan = effective_plan(principal)
        return {"plan": plan, "billing_enabled": False, "full_scan_access": plan in ("full", "team")}

    @app.post("/account/consultation", include_in_schema=False)
    async def consultation(request: Request):
        principal = _registered_principal(request)
        try:
            payload = ConsultationInput.model_validate(await request.json())
        except (ValueError, TypeError, UnicodeError, RecursionError, ValidationError):
            raise HTTPException(422, "Invalid consultation request.") from None
        result = await asyncio.to_thread(_request_consultation, principal, payload.message)
        return JSONResponse(result, status_code=201)

    @app.get("/account/consultation", include_in_schema=False)
    def consultation_status(request: Request):
        return _latest_consultation(_registered_principal(request))
