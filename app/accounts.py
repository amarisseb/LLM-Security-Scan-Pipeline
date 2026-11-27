"""Durable self-service identities; no mail, billing or verification claims.

ARISEC_ACCOUNTS_DB defaults to .arisec-private/accounts.sqlite3. connect_db()
returns an initialized sqlite3 connection with Row results; callers must close it.
Only server code may grant_origin(id, origin) after proving target control.
reserve_free_scan(principal, peer_ip, unique_scan_id) must precede guest queueing;
refund_free_scan(scan_id) is for queue failure/failed jobs only, never success.
Guest allowance is one per principal AND network (/24 IPv4, /64 IPv6), durable
across new cookies and signup. Registered scans use the existing hour/day limits.
Store this database privately and back it up; it contains personal data and hashes.
"""

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from .target_control import canonical_origin

PBKDF2_ITERATIONS = 600_000
SESSION_SECONDS = 7 * 24 * 60 * 60
COOKIE_NAME = "arisec_session"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
 id TEXT PRIMARY KEY, email TEXT UNIQUE, password_salt BLOB, password_hash BLOB,
 created_at REAL NOT NULL,
 CHECK ((email IS NULL AND password_salt IS NULL AND password_hash IS NULL)
 OR (email IS NOT NULL AND password_salt IS NOT NULL AND password_hash IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS sessions (
 token_sha256 TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES accounts(id),
 expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS session_principal ON sessions(principal_id);
CREATE TABLE IF NOT EXISTS allowed_origins (
 principal_id TEXT NOT NULL REFERENCES accounts(id), origin TEXT NOT NULL,
 PRIMARY KEY(principal_id, origin)
);
CREATE TABLE IF NOT EXISTS guest_reservations (
 scan_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES accounts(id),
 network_hash TEXT NOT NULL, refunded INTEGER NOT NULL DEFAULT 0 CHECK(refunded IN (0,1))
);
CREATE UNIQUE INDEX IF NOT EXISTS guest_principal_credit
 ON guest_reservations(principal_id) WHERE refunded=0;
CREATE UNIQUE INDEX IF NOT EXISTS guest_network_credit
 ON guest_reservations(network_hash) WHERE refunded=0;
CREATE TABLE IF NOT EXISTS auth_attempts (
 bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at REAL NOT NULL
);
"""


def enabled() -> bool:
    return os.getenv("ARISEC_SELF_SERVE") == "1"


def connect_db() -> sqlite3.Connection:
    path = Path(os.getenv("ARISEC_ACCOUNTS_DB", ".arisec-private/accounts.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        # SQLite otherwise creates new files using the process umask. Keep new
        # databases private on POSIX; Windows inherits the operator folder ACL.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
    db = sqlite3.connect(str(path), timeout=5)
    try:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript(_SCHEMA)
        return db
    except Exception:
        db.close()
        raise


def _principal(db, row):
    return {"id": row["id"], "email": row["email"], "guest": row["email"] is None,
            "local_demo": False,
            "allowed_origins": [r[0] for r in db.execute("SELECT origin FROM allowed_origins WHERE principal_id=? ORDER BY origin", (row["id"],))]}


def _session(db, principal_id):
    token = secrets.token_urlsafe(32)
    db.execute("DELETE FROM sessions WHERE expires_at<=?", (time.time(),))
    db.execute("INSERT INTO sessions VALUES (?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), principal_id, time.time() + SESSION_SECONDS))
    return token


def _token_hash(token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        return None
    return hashlib.sha256(token.encode()).hexdigest()


def session_principal(token):
    digest = _token_hash(token)
    if digest is None:
        return None
    with closing(connect_db()) as db:
        row = db.execute("SELECT a.* FROM accounts a JOIN sessions s ON a.id=s.principal_id WHERE s.token_sha256=? AND s.expires_at>?", (digest, time.time())).fetchone()
        return _principal(db, row) if row else None


def create_guest_session():
    with closing(connect_db()) as db, db:
        principal_id = secrets.token_hex(16)
        db.execute("INSERT INTO accounts(id,created_at) VALUES (?,?)", (principal_id, time.time()))
        token = _session(db, principal_id)
        row = db.execute("SELECT * FROM accounts WHERE id=?", (principal_id,)).fetchone()
        return _principal(db, row), token


def validate_credentials(email, password):
    """Normalize email; passwords are used verbatim and never stripped/truncated."""
    if not isinstance(email, str) or not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValueError("Invalid credentials")
    # Reject unencodable input before hashing; ASCII emails keep identity matching
    # predictable without adding dependencies or pretending to verify delivery.
    password.encode("utf-8")
    email = email.strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}", email):
        raise ValueError("Invalid credentials")
    return email, password


def _password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


def signup(principal, email, password):
    email, password = validate_credentials(email, password)
    salt = secrets.token_bytes(32)
    password_hash = _password_hash(password, salt)
    try:
        with closing(connect_db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            principal_id = principal["id"] if principal else secrets.token_hex(16)
            if principal:
                row = db.execute("SELECT * FROM accounts WHERE id=?", (principal_id,)).fetchone()
                if not row or row["email"] is not None:
                    raise ValueError("Account unavailable")
                db.execute("UPDATE accounts SET email=?,password_salt=?,password_hash=? WHERE id=?", (email, salt, password_hash, principal_id))
            else:
                db.execute("INSERT INTO accounts VALUES (?,?,?,?,?)", (principal_id, email, salt, password_hash, time.time()))
            db.execute("DELETE FROM sessions WHERE principal_id=?", (principal_id,))
            token = _session(db, principal_id)
            return _principal(db, db.execute("SELECT * FROM accounts WHERE id=?", (principal_id,)).fetchone()), token
    except sqlite3.IntegrityError:
        raise ValueError("Account unavailable") from None


def login(email, password, previous_token=None):
    email, password = validate_credentials(email, password)
    with closing(connect_db()) as db, db:
        row = db.execute("SELECT * FROM accounts WHERE email=?", (email,)).fetchone()
        # Unknown accounts do equal password work; credentials never enter logs.
        salt = row["password_salt"] if row else b"\0" * 32
        digest = _password_hash(password, salt)
        expected = row["password_hash"] if row else b"\0" * 32
        if not hmac.compare_digest(digest, expected) or row is None:
            raise ValueError("Invalid credentials")
        db.execute("DELETE FROM sessions WHERE token_sha256=?", (_token_hash(previous_token),))
        token = _session(db, row["id"])
        return _principal(db, row), token


def logout(token):
    with closing(connect_db()) as db, db:
        db.execute("DELETE FROM sessions WHERE token_sha256=?", (_token_hash(token),))


def grant_origin(principal_id, origin, *, db=None):
    """Server-only grant, no DNS. Supplied db stays in the caller's transaction."""
    origin = canonical_origin(origin, origin_only=True)
    if db is not None:
        db.execute("INSERT OR IGNORE INTO allowed_origins VALUES (?,?)", (principal_id, origin))
        return
    with closing(connect_db()) as connection, connection:
        connection.execute("INSERT OR IGNORE INTO allowed_origins VALUES (?,?)", (principal_id, origin))


def _network_hash(ip):
    address = ipaddress.ip_address(ip)
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    network = ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 64}", strict=False)
    return hashlib.sha256(str(network).encode()).hexdigest()


def free_scan_available(principal, ip):
    if not principal or not principal.get("id"):
        return False
    try:
        network = _network_hash(ip)
    except ValueError:
        return False
    with closing(connect_db()) as db:
        return db.execute("SELECT 1 FROM guest_reservations WHERE refunded=0 AND (principal_id=? OR network_hash=?) LIMIT 1", (principal["id"], network)).fetchone() is None


def reserve_free_scan(principal, ip, scan_id) -> bool:
    if not principal or not principal.get("id"):
        return False
    if not isinstance(scan_id, str) or not 1 <= len(scan_id) <= 128:
        return False
    try:
        network = _network_hash(ip)
    except ValueError:
        return False
    try:
        with closing(connect_db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT email FROM accounts WHERE id=?", (principal["id"],)).fetchone()
            if row is None:
                return False
            db.execute("INSERT INTO guest_reservations(scan_id,principal_id,network_hash) VALUES (?,?,?)", (scan_id, principal["id"], network))
            return True
    except sqlite3.IntegrityError:
        return False


def refund_free_scan(scan_id):
    with closing(connect_db()) as db, db:
        db.execute("UPDATE guest_reservations SET refunded=1 WHERE scan_id=?", (scan_id,))


def allow_auth_attempt(ip, *, limit=10, window_seconds=900):
    """Durable shared signup/login IP throttle, called BEFORE password hashing."""
    bucket = hashlib.sha256(str(ip).encode()).hexdigest()
    now = time.time()
    with closing(connect_db()) as db, db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM auth_attempts WHERE expires_at<=?", (now,))
        row = db.execute("SELECT count FROM auth_attempts WHERE bucket=?", (bucket,)).fetchone()
        if row and row[0] >= limit:
            return False
        if row:
            db.execute("UPDATE auth_attempts SET count=count+1 WHERE bucket=?", (bucket,))
        else:
            db.execute("INSERT INTO auth_attempts VALUES (?,?,?)", (bucket, 1, now + window_seconds))
        return True
