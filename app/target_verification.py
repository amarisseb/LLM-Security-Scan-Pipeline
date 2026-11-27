"""Public HTTPS file challenges; mount behind SecurityBoundaryMiddleware."""
import hashlib
import hmac
import http.client
import secrets
import threading
import time
from contextlib import closing
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, StrictStr

from . import accounts, application_generator as transport, url_safety
from .security import principal_for
from .target_control import canonical_origin

LIFETIME = 900
MAX_BYTES = 4096
REQUEST_TIMEOUT = 5
WELL_KNOWN = "/.well-known/arisec-verification.txt"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS verification_challenges (
 id TEXT PRIMARY KEY,
 principal_id TEXT NOT NULL REFERENCES accounts(id),
 origin TEXT NOT NULL,
 token_digest TEXT NOT NULL,
 expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS verification_principal ON verification_challenges(principal_id);
"""


class ChallengeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_url: StrictStr


class CompleteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: StrictStr


def _db():
    db = accounts.connect_db()
    try:
        db.executescript(_SCHEMA)
        return db
    except Exception:
        db.close()
        raise


def _origin(target):
    try:
        if not isinstance(target, str) or not 1 <= len(target) <= 8192 or "?" in target or "#" in target:
            raise ValueError()
        origin = canonical_origin(target)
        parts = urlsplit(origin)
        if (parts.scheme != "https" or (parts.port or 443) in url_safety.BLOCKED_PORTS
                or parts.hostname in url_safety.BLOCKED_HOSTNAMES
                or parts.hostname.endswith(".localhost")):
            raise ValueError()
        return origin
    except (ValueError, TypeError, UnicodeError):
        raise HTTPException(400, "A public HTTPS target without credentials, query or fragment is required.") from None


def _resolve(origin):
    parts = urlsplit(origin)
    return transport._resolve_public(parts.hostname, parts.port or 443)


def _fetch_token(origin):
    """No proxy, redirects, cookies or authorization; one pinned HTTPS GET."""
    deadline = time.monotonic() + REQUEST_TIMEOUT
    connection = watchdog = None
    try:
        address = _resolve(origin)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        parts = urlsplit(origin)
        connection = transport._PinnedHTTPSConnection(parts.hostname, parts.port or 443, address, remaining)
        watchdog = threading.Timer(remaining, connection.abort)
        watchdog.daemon = True
        watchdog.start()
        connection.request("GET", WELL_KNOWN, headers={"Accept": "text/plain", "Accept-Encoding": "identity"})
        tls_socket = connection.sock
        tls_socket.settimeout(max(0.001, deadline - time.monotonic()))
        response = connection.getresponse()
        if response.status != 200 or response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError()
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            tls_socket.settimeout(remaining)
            chunk = response.read1(MAX_BYTES + 1 - size)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError()
            chunks.append(chunk)
        if time.monotonic() >= deadline:
            raise TimeoutError()
        return b"".join(chunks).strip()
    except (OSError, ValueError, http.client.HTTPException, transport.ApplicationRequestError):
        raise HTTPException(400, "The verification file could not be verified.") from None
    finally:
        if watchdog:
            watchdog.cancel()
        if connection:
            connection.close()


def _row(db, challenge_id, principal_id):
    row = db.execute("SELECT * FROM verification_challenges WHERE id=? AND principal_id=? AND expires_at>?",
                     (challenge_id, principal_id, time.time())).fetchone()
    if row is None:
        raise HTTPException(404, "Challenge unavailable or expired.")
    return row


def register_verification_routes(app):
    @app.post("/verification/challenge")
    def challenge(body: ChallengeInput, request: Request):
        if not accounts.enabled():
            raise HTTPException(404, "Not found.")
        principal = principal_for(request)
        origin = _origin(body.target_url)
        try:
            _resolve(origin)  # bounded public-address validation, repeated at fetch
        except transport.ApplicationRequestError:
            raise HTTPException(400, "A reachable public HTTPS target is required.") from None
        token = secrets.token_urlsafe(32)
        challenge_id = secrets.token_urlsafe(24)
        with closing(_db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            now = time.time()
            db.execute("DELETE FROM verification_challenges WHERE expires_at<=?", (now,))
            count = db.execute("SELECT count(*) FROM verification_challenges WHERE principal_id=?", (principal["id"],)).fetchone()[0]
            if count >= 4:
                raise HTTPException(429, "At most four active challenges are allowed.")
            db.execute("INSERT INTO verification_challenges VALUES (?,?,?,?,?)",
                       (challenge_id, principal["id"], origin, hashlib.sha256(token.encode()).hexdigest(), now + LIFETIME))
        return {"challenge_id": challenge_id, "verification_url": origin + WELL_KNOWN,
                "verification_token": token, "expires_in": LIFETIME,
                "instructions": "Serve verification_token as the plain text file at verification_url, then complete this challenge within 15 minutes. Redirects are not accepted."}

    @app.post("/verification/complete")
    def complete(body: CompleteInput, request: Request):
        if not accounts.enabled():
            raise HTTPException(404, "Not found.")
        principal = principal_for(request)
        if not 1 <= len(body.challenge_id) <= 128:
            raise HTTPException(404, "Challenge unavailable or expired.")
        with closing(_db()) as db:
            row = _row(db, body.challenge_id, principal["id"])
        digest = hashlib.sha256(_fetch_token(row["origin"])).hexdigest()
        if not hmac.compare_digest(digest, row["token_digest"]):
            raise HTTPException(400, "The verification file could not be verified.")
        with closing(_db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            current = _row(db, body.challenge_id, principal["id"])
            if not hmac.compare_digest(digest, current["token_digest"]):
                raise HTTPException(400, "The verification file could not be verified.")
            accounts.grant_origin(principal["id"], current["origin"], db=db)
            db.execute("DELETE FROM verification_challenges WHERE id=?", (body.challenge_id,))
        return {"verified": True, "origin": row["origin"]}
