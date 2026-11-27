"""Include router in main; SecurityBoundaryMiddleware must be outermost.

GET /account/session creates an anonymous guest if needed and sets a host-only
arisec_session cookie. POST /account/{signup,login} accepts {email,password};
POST /account/logout revokes the current session. Mutations require same-origin
Origin (including CLI); GET may omit Origin. Boundary applies TLS, CSRF, body
and early IP throttles. Do not mount these routes without that boundary.
Signup promotes the current guest ID and rotates/revokes old sessions so reports
stay owned by the same principal. Emails are NOT verified. No reset/mail service.
"""

import asyncio
import sqlite3

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import JSONResponse

from . import accounts

router = APIRouter(prefix="/account", include_in_schema=False)


def _require_boundary(request):
    if not accounts.enabled() or not getattr(request.state, "account_boundary", False):
        raise HTTPException(404, "Not found.")


def _cookie(request, response, token):
    response.set_cookie(accounts.COOKIE_NAME, token, max_age=accounts.SESSION_SECONDS,
                        httponly=True, secure=not request.state.local_preview,
                        samesite="lax", path="/")


def _payload(principal, ip):
    return {"authenticated": not principal["guest"], "guest": principal["guest"],
            "email": principal["email"], "free_scan_available": accounts.free_scan_available(principal, ip)}


@router.get("/session")
def session(request: Request):
    _require_boundary(request)
    try:
        principal = getattr(request.state, "principal", None)
        token = None
        if principal is None:
            principal, token = accounts.create_guest_session()
        response = JSONResponse(_payload(principal, request.client.host))
        if token:
            _cookie(request, response, token)
        return response
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "Service unavailable.") from None


async def _credentials(request):
    try:
        body = await request.json()
        if not isinstance(body, dict) or set(body) != {"email", "password"}:
            raise ValueError()
        return accounts.validate_credentials(body["email"], body["password"])
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise HTTPException(400, "Invalid credentials.") from None


@router.post("/signup")
async def signup(request: Request):
    _require_boundary(request)
    email, password = await _credentials(request)
    try:
        principal, token = await asyncio.to_thread(accounts.signup, getattr(request.state, "principal", None), email, password)
        response = JSONResponse(await asyncio.to_thread(_payload, principal, request.client.host), status_code=201)
        _cookie(request, response, token)
        return response
    except (ValueError, UnicodeError):
        raise HTTPException(400, "Account could not be created.") from None
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "Service unavailable.") from None


@router.post("/login")
async def login(request: Request):
    _require_boundary(request)
    email, password = await _credentials(request)
    try:
        principal, token = await asyncio.to_thread(accounts.login, email, password, request.state.session_token)
        response = JSONResponse(await asyncio.to_thread(_payload, principal, request.client.host))
        _cookie(request, response, token)
        return response
    except (ValueError, UnicodeError):
        raise HTTPException(401, "Invalid credentials.") from None
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "Service unavailable.") from None


@router.post("/logout")
def logout(request: Request):
    _require_boundary(request)
    try:
        accounts.logout(request.state.session_token)
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "Service unavailable.") from None
    response = JSONResponse({"authenticated": False, "guest": False, "email": None, "free_scan_available": False})
    response.delete_cookie(accounts.COOKIE_NAME, path="/", secure=not request.state.local_preview, httponly=True, samesite="lax")
    return response
