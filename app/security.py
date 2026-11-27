"""Legacy pilot and opt-in self-service ASGI boundary.

ARISEC_SELF_SERVE=1 enables session guests/accounts on /scan and /verification,
and protects /account with transport, CSRF, body and early request limits.
Self-service cookies require same-origin Origin on mutations; legacy Bearer
authentication remains available with optional operator account configuration.
ARISEC_LOCAL_PREVIEW=1 permits HTTP cookies only for verified loopback local
Host/Origin requests. It never bypasses authentication or target-control checks.
Default app.main remains legacy; app.pilot opts in before importing main.

Wrap the application outermost with SecurityBoundaryMiddleware (or add it last).
All /scan and /scan/* methods authenticate, require TLS, rate limit, and buffer
at most 128 KiB within 10 seconds before calling application code. Proxy trust belongs in uvicorn;
this module never trusts forwarded headers. GET /security-config is public.
Use principal_for(request), then require_target_control(principal, url) before
DNS/queueing for web/http scans. Scope result access by principal ID separately.
Set ARISEC_ACCOUNTS_FILE to an operator-controlled JSON array containing only
id, email, token_sha256, allowed_origins. Tokens must be high-entropy random
secrets generated using secrets.token_urlsafe(32) or equivalent and delivered
out of band. The boundary enforces URL-safe syntax and at least 32 characters;
entropy cannot be verified from operator hashes. No registration or config logs.
ARISEC_LOCAL_DEMO=1 is launcher-only and bypasses authentication solely on a
loopback peer with a local Host at the ASGI server port and same-origin browser
metadata. It grants no target origins; a launcher/integrator must explicitly
handle its existing local-lab policy. Rate limits are per worker; multi-worker
deployments also need a shared upstream limiter. Restrict file write access.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import HTTPException
from starlette.responses import JSONResponse

from .target_control import canonical_origin
from . import accounts as account_store

MAX_BODY_BYTES = 128 * 1024
MAX_ACCOUNTS_BYTES = 1024 * 1024
BODY_READ_TIMEOUT_SECONDS = 10.0


def _local_request(scope):
    """Check a loopback peer and same-origin local authority, without bypasses.

    No DNS or forwarded headers: Host must name localhost or a numeric loopback
    address at the actual ASGI server port. Browser requests must be same-origin.
    CLI clients may omit Origin and Sec-Fetch-Site.
    """
    try:
        if not ipaddress.ip_address(scope["client"][0]).is_loopback:
            return False
        scheme = scope["scheme"]
        if scheme not in ("http", "https"):
            return False
        headers = scope.get("headers", [])
        hosts = [v.decode("ascii") for k, v in headers if k.lower() == b"host"]
        origins = [v.decode("ascii") for k, v in headers if k.lower() == b"origin"]
        fetch_sites = [v.decode("ascii") for k, v in headers if k.lower() == b"sec-fetch-site"]
        if len(hosts) != 1 or len(origins) > 1 or len(fetch_sites) > 1:
            return False
        if fetch_sites and fetch_sites[0] not in ("same-origin", "none"):
            return False
        authority = canonical_origin(f"{scheme}://{hosts[0]}", origin_only=True)
        # Host is an authority, not a URL: reject even an otherwise valid '/'.
        if any(c in hosts[0] for c in "/?#"):
            return False
        parts = urlsplit(authority)
        if parts.hostname != "localhost" and not ipaddress.ip_address(parts.hostname).is_loopback:
            return False
        port = parts.port or {"http": 80, "https": 443}[scheme]
        if port != scope["server"][1]:
            return False
        if origins and canonical_origin(origins[0], origin_only=True) != authority:
            return False
        return True
    except (KeyError, IndexError, TypeError, ValueError, UnicodeError):
        return False


def _demo(scope):
    return not account_store.enabled() and os.getenv("ARISEC_LOCAL_DEMO") == "1" and _local_request(scope)


def local_preview_allowed(scope):
    """HTTP cookie transport exception only; never an auth or target grant."""
    return os.getenv("ARISEC_LOCAL_PREVIEW") == "1" and scope.get("scheme") == "http" and _local_request(scope)


def _same_origin(scope, *, required=False):
    try:
        headers = scope.get("headers", [])
        hosts = [v.decode("ascii") for k, v in headers if k.lower() == b"host"]
        origins = [v.decode("ascii") for k, v in headers if k.lower() == b"origin"]
        sites = [v.decode("ascii") for k, v in headers if k.lower() == b"sec-fetch-site"]
        if len(hosts) != 1 or len(origins) > 1 or len(sites) > 1:
            return False
        if sites and sites[0] not in ("same-origin", "none"):
            return False
        if any(c in hosts[0] for c in "/?#"):
            return False
        authority = canonical_origin(f"{scope['scheme']}://{hosts[0]}", origin_only=True)
        if not origins:
            return not required
        return canonical_origin(origins[0], origin_only=True) == authority
    except (KeyError, ValueError, TypeError, UnicodeError):
        return False


def _session_token(scope):
    """Reject ambiguous/duplicate cookies instead of selecting an arbitrary one."""
    values = []
    try:
        raw = b";".join(v for k, v in scope.get("headers", []) if k.lower() == b"cookie")
        if len(raw) > 8192:
            return None
        for item in raw.decode("ascii").split(";"):
            key, sep, value = item.strip().partition("=")
            if key == account_store.COOKIE_NAME and sep:
                values.append(value)
        return values[0] if len(values) == 1 else None
    except UnicodeError:
        return None


def local_demo_allowed(request) -> bool:
    """Check launcher flag, peer, local Host/port and browser origin metadata."""
    return _demo(request.scope)


def principal_for(request) -> dict:
    """Return the boundary's principal; do not derive identity from JSON input."""
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, dict):
        raise HTTPException(status_code=401, detail="Authentication required.")
    return principal


def _accounts():
    path = os.environ.get("ARISEC_ACCOUNTS_FILE")
    if not path:
        raise ValueError("Configuration unavailable")
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_ACCOUNTS_BYTES + 1)
    if len(raw) > MAX_ACCOUNTS_BYTES:
        raise ValueError("Configuration unavailable")
    entries = json.loads(raw)
    if not isinstance(entries, list) or not entries or len(entries) > 1000:
        raise ValueError("Configuration unavailable")
    ids, hashes = set(), set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "email", "token_sha256", "allowed_origins"}:
            raise ValueError("Configuration unavailable")
        if any(not isinstance(entry[k], str) or not entry[k] or len(entry[k]) > 320 or any(ord(c) < 32 for c in entry[k]) for k in ("id", "email")):
            raise ValueError("Configuration unavailable")
        digest = entry["token_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or digest in hashes or entry["id"] in ids:
            raise ValueError("Configuration unavailable")
        origins = entry["allowed_origins"]
        if not isinstance(origins, list) or len(origins) > 100:
            raise ValueError("Configuration unavailable")
        entry["allowed_origins"] = [canonical_origin(o, origin_only=True) for o in origins]
        ids.add(entry["id"])
        hashes.add(digest)
    return entries


class SecurityBoundaryMiddleware:
    """Pure ASGI boundary; configurable fixed-window limits for embedding/tests."""

    def __init__(self, app, *, ip_limit=120, principal_limit=60, window_seconds=60, max_rate_keys=10000):
        if min(ip_limit, principal_limit, window_seconds, max_rate_keys) <= 0:
            raise ValueError("Limits must be positive")
        self.app = app
        self.ip_limit, self.principal_limit = ip_limit, principal_limit
        self.window_seconds, self.max_rate_keys = window_seconds, max_rate_keys
        self._rates = {}
        self._lock = threading.Lock()

    def _allow(self, key, limit):
        now = time.monotonic()
        with self._lock:
            for expired in [k for k, (_, end) in self._rates.items() if end <= now]:
                del self._rates[expired]
            if key not in self._rates and len(self._rates) >= self.max_rate_keys:
                return False
            count, end = self._rates.get(key, (0, now + self.window_seconds))
            self._rates[key] = (count + 1, end)
            return count < limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in (b"x-content-type-options", b"referrer-policy", b"cache-control", b"strict-transport-security")]
                headers += [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"), (b"cache-control", b"no-store")]
                if scope.get("scheme") == "https":
                    headers.append((b"strict-transport-security", b"max-age=31536000"))
                message = {**message, "headers": headers}
            await send(message)

        async def reject(code, detail):
            await JSONResponse({"detail": detail}, status_code=code)(scope, receive, secure_send)

        path = scope.get("path", "")
        self_serve = account_store.enabled()
        demo = _demo(scope)
        if path == "/security-config" and scope["method"] == "GET":
            await JSONResponse({"authentication_required": not demo, "web_scanning_available": demo})(scope, receive, secure_send)
            return
        account_path = self_serve and (path == "/account" or path.startswith("/account/"))
        verification_path = self_serve and (path == "/verification" or path.startswith("/verification/"))
        if not account_path and not verification_path and path != "/scan" and not path.startswith("/scan/"):
            await self.app(scope, receive, secure_send)
            return
        state = scope.setdefault("state", {})
        for name in ("principal", "account_boundary", "session_token", "local_preview"):
            state.pop(name, None)
        peer = (scope.get("client") or ("unknown",))[0]
        if not self._allow(("ip", peer), self.ip_limit):
            await reject(429, "Request limit reached.")
            return
        preview = self_serve and local_preview_allowed(scope)
        if scope.get("scheme") != "https" and not demo and not preview:
            await reject(403, "Request denied.")
            return
        method = scope.get("method")
        mutation = method not in ("GET", "HEAD", "OPTIONS")
        cookie_token = _session_token(scope) if self_serve else None
        auth = [v for k, v in scope.get("headers", []) if k.lower() == b"authorization"]
        if self_serve and (account_path or (cookie_token and not auth)):
            if not _same_origin(scope, required=mutation):
                await reject(403, "Request denied.")
                return
        if account_path and method == "POST" and path in ("/account/signup", "/account/login"):
            try:
                allowed = await asyncio.to_thread(account_store.allow_auth_attempt, peer)
            except (OSError, sqlite3.Error):
                await reject(503, "Service unavailable.")
                return
            if not allowed:
                await reject(429, "Request limit reached.")
                return
        if method == "OPTIONS":
            # CORS preflights do not carry the bearer token. The inner CORS
            # middleware checks the configured origin; no scan route is run.
            await self.app(scope, receive, secure_send)
            return
        principal = None
        if demo:
            principal = {"id": "local-demo", "email": "", "allowed_origins": [], "local_demo": True}
        elif self_serve and (account_path or not auth):
            try:
                principal = await asyncio.to_thread(account_store.session_principal, cookie_token)
            except (OSError, sqlite3.Error):
                await reject(503, "Service unavailable.")
                return
        else:
            try:
                accounts = [] if self_serve and not os.getenv("ARISEC_ACCOUNTS_FILE") else _accounts()
            except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
                await reject(503, "Service unavailable.")
                return
            if len(auth) == 1 and len(auth[0]) <= 8192:
                match = re.fullmatch(rb"(?i:Bearer) ([A-Za-z0-9_-]{32,})", auth[0])
                if match:
                    digest = hashlib.sha256(match[1]).hexdigest()
                    for account in accounts:
                        if hmac.compare_digest(digest, account["token_sha256"]):
                            principal = {k: account[k] for k in ("id", "email", "allowed_origins")}
                            principal["local_demo"] = False
                            if self_serve:
                                principal["guest"] = False
        if principal is None and not account_path:
            await reject(401, "Authentication required.")
            return
        if principal is not None and not self._allow(("principal", principal["id"]), self.principal_limit):
            await reject(429, "Request limit reached.")
            return
        if principal is not None:
            state["principal"] = principal
        if account_path:
            state.update(account_boundary=True, session_token=cookie_token, local_preview=preview)
        body = bytearray()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + BODY_READ_TIMEOUT_SECONDS
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                await reject(408, "Request timed out.")
                return
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except asyncio.TimeoutError:
                await reject(408, "Request timed out.")
                return
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                await reject(400, "Invalid request.")
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                await reject(413, "Request too large.")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def buffered_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, buffered_receive, secure_send)
