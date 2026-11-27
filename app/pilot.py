"""Hosted UI/API entry point. Never import the development demo launcher here."""
import base64
import hashlib
import os
from pathlib import Path
import re

if os.getenv("ARISEC_LOCAL_DEMO") == "1":
    raise RuntimeError("The hosted pilot must not enable the local demo bypass.")

# Only this entry point opts in by default; importing app.main stays legacy.
os.environ.setdefault("ARISEC_SELF_SERVE", "1")

from fastapi.responses import HTMLResponse
from .security import _accounts
from . import accounts

try:
    if accounts.enabled():
        accounts.connect_db().close()
    else:
        _accounts()
except Exception:
    raise RuntimeError("Account storage/configuration is unavailable.") from None

from .main import app

_PAGE = Path(__file__).resolve().parents[1] / "demo" / "index.html"


def pilot_page():
    # Same-source fonts keep invite credentials/report browsing off third-party
    # requests. Inline script is hash-authorised; target text is never HTML.
    html = _PAGE.read_text(encoding="utf-8")
    html = re.sub(r'<link\b[^>]*href="https://fonts\.googleapis\.com[^>]*>\s*', '', html)
    scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', html, re.S)
    hashes = ["'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'" for s in scripts]
    policy = ("default-src 'self'; script-src " + ' '.join(hashes) + "; "
              "style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; "
              "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
    return HTMLResponse(html, headers={"Content-Security-Policy": policy})


app.add_api_route("/", pilot_page, methods=["GET"], include_in_schema=False)
