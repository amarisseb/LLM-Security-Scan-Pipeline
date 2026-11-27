"""Offline operator grants, not automatic proof of ownership.

Call require_target_control(principal_for(request), target_url) for web/http
scans BEFORE DNS validation or queueing. Keep the existing SSRF checks as well.
Only the operator may grant origins after manually verifying control offline.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from fastapi import HTTPException


def canonical_origin(url: str, *, origin_only: bool = False) -> str:
    """Normalize scheme/IDNA host/default port without any network operations."""
    if not isinstance(url, str) or not url or len(url) > 8192:
        raise ValueError("Invalid origin")
    if any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url or "#" in url:
        raise ValueError("Invalid origin")
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.netloc or "@" in parts.netloc:
        raise ValueError("Invalid origin")
    if origin_only and (parts.path not in ("", "/") or parts.query or "?" in url):
        raise ValueError("Invalid origin")
    host = parts.hostname
    if not host or "%" in host or host.endswith(".") or parts.netloc.endswith(":"):
        raise ValueError("Invalid origin")
    try:
        address = ipaddress.ip_address(host)
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        host = host.encode("idna").decode("ascii").lower()
        if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
            raise ValueError("Invalid origin")
    port = parts.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid origin")
    suffix = f":{port}" if port is not None and port != {"https": 443, "http": 80}[parts.scheme] else ""
    return f"{parts.scheme}://{host}{suffix}"


def require_target_control(principal: dict, url: str) -> None:
    """Require an exact operator-approved origin; never accept request claims.

Pass ONLY the authenticated principal returned by security.principal_for.
Local demo authentication does not implicitly grant arbitrary target origins.
"""
    try:
        origin = canonical_origin(url)
        allowed = principal["allowed_origins"]
        if not isinstance(allowed, (list, tuple)):
            raise ValueError("Invalid grants")
        if origin in {canonical_origin(item, origin_only=True) for item in allowed}:
            return
    except (ValueError, TypeError, KeyError, UnicodeError):
        pass
    raise HTTPException(status_code=403, detail="Target not approved.")
