"""Authorization attestation: the user's statement that they may test the target.

Every scan start writes one line to an append-only JSONL log with the time, IP,
email, target URL and the *version* of the statement shown. Versions are how a
later wording change stays honest: an old log line still says exactly which text
that person agreed to.

RULES FOR EDITING THE TEXT
  * Never edit a published entry in ATTESTATION_TEXTS. Add a new version number
    with the new wording; the highest number is the current one.
  * Old entries must stay in this file for as long as their log lines exist.
  * Each log line also stores a SHA-256 of the text, so a line can be checked
    against the entry it names.

The wording below is a draft. Have counsel review it before real users see it.
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

ATTESTATION_TEXTS: dict[int, str] = {
    1: (
        "I confirm that I own the website or system at the URL I am submitting, or "
        "that I have the owner's explicit permission to run security testing against it. "
        "I understand that this scan sends automated adversarial messages to the target "
        "(including prompt-injection, jailbreak and data-extraction attempts) and may "
        "generate unusual or unsafe responses and load on the target. I accept "
        "responsibility for scanning this target, and I will not use this service to "
        "test systems I am not authorized to test."
    ),
    # Added when direct API-key scanning shipped: version 1 only covers "a URL
    # I'm authorized to test," which doesn't fit submitting your own API
    # credential. This version covers both without changing what version-1
    # scans are shown.
    2: (
        "I confirm that I am authorized to direct this scan at the target I am "
        "submitting: either I own the website or system at the URL, or I own or am "
        "authorized to use the API credential I am providing. I understand that this "
        "scan sends automated adversarial messages to the target (including "
        "prompt-injection, jailbreak and data-extraction attempts) and may generate "
        "unusual or unsafe responses. For a scan run against an API credential, I "
        "understand this will consume that account's quota, may incur real cost, and "
        "that I am responsible for complying with the provider's own usage policies. "
        "I accept responsibility for this scan, and I will not use this service to "
        "test systems or credentials I am not authorized to use."
    ),
}

CURRENT_ATTESTATION_VERSION = max(ATTESTATION_TEXTS)

_DEFAULT_LOG_PATH = "attestation_log/attestations.jsonl"

_write_lock = threading.Lock()


def current_attestation() -> dict:
    """What the frontend should display, and the version it must send back."""
    return {
        "version": CURRENT_ATTESTATION_VERSION,
        "text": ATTESTATION_TEXTS[CURRENT_ATTESTATION_VERSION],
    }


def log_attestation(
    *,
    ip: str,
    user_email: str,
    target_url: str,
    version: int = CURRENT_ATTESTATION_VERSION,
    skip_ai_check: bool = False,
    mode: str = "web",
    log_path: str | os.PathLike | None = None,
) -> dict:
    """Append one attestation record and return it.

    `target_url` is the human-readable target descriptor: the real URL for a
    web scan, or "provider/model" for an API scan -- NEVER the API key itself.

    Raises if the record can't be written durably. Callers must treat that as
    "do not start the scan": no scan without a record that it was authorized.
    """
    text = ATTESTATION_TEXTS[version]
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "user_email": user_email,
        "mode": mode,
        "target_url": target_url,
        "attestation_version": version,
        "attestation_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        # Overriding the "does it answer like an AI" gate is a decision the user
        # made about their target, so it belongs on the record. Not meaningful
        # for an API scan (there's no such gate), always False there.
        "skip_ai_check": skip_ai_check,
    }

    path = Path(log_path or os.getenv("ATTESTATION_LOG_PATH", _DEFAULT_LOG_PATH))
    path.parent.mkdir(parents=True, exist_ok=True)
    # U+0085 (NEL), U+2028 and U+2029 are legal inside a JSON string but
    # str.splitlines() treats them as line breaks, so a URL containing one could
    # split a record in two for anyone reading the log that way. Escape them.
    line = json.dumps(record, ensure_ascii=False)
    line = line.replace("\u0085", "\\u0085").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029") + "\n"
    with _write_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
    return record
