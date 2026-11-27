"""Offline operator invite provisioning; no registration or target-grant API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.target_control import canonical_origin


def issue_invite(config_path, account_id, email, origins, evidence):
    if not account_id or not email or '@' not in email or not evidence.strip():
        raise ValueError('An account ID, email and control-verification evidence are required.')
    if any(ord(c) < 32 for c in account_id + email) or max(len(account_id), len(email)) > 320:
        raise ValueError('Invalid account identity.')
    origins = list(dict.fromkeys(canonical_origin(o, origin_only=True) for o in origins))
    if any(not o.startswith('https://') for o in origins):
        raise ValueError('Hosted pilot origins must use HTTPS.')
    path = Path(config_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = path.with_name(path.name + '.lock')
    lock.mkdir()  # Single operator transaction; never overwrite concurrent changes.
    temp = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    try:
        entries = json.loads(path.read_text()) if path.exists() else []
        if not isinstance(entries, list) or len(entries) >= 1000:
            raise ValueError('Invalid or full account configuration.')
        entries = [a for a in entries if a['id'] != account_id]
        token = secrets.token_urlsafe(32)
        entries.append(dict(id=account_id, email=email,
                            token_sha256=hashlib.sha256(token.encode()).hexdigest(), allowed_origins=origins))
        record = dict(timestamp=datetime.now(timezone.utc).isoformat(), account_id=account_id,
                      approved_origins=origins, verification_evidence=evidence)
        # Evidence is private too. Commit the audit entry before granting access.
        with open(path.with_name('control-approvals.jsonl'), 'a', encoding='utf-8') as log:
            log.write(json.dumps(record) + '\n')
        descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(entries, stream, indent=2)
        os.replace(temp, path)
        return token
    finally:
        if temp.exists():
            temp.unlink()
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='.arisec-private/accounts.json')
    parser.add_argument('--id', required=True)
    parser.add_argument('--email', required=True)
    parser.add_argument('--origin', action='append', default=[])
    parser.add_argument('--control-evidence', required=True,
                        help='Operator record of scope and how target control was verified; never put credentials here.')
    args = parser.parse_args()
    token = issue_invite(args.config, args.id, args.email, args.origin, args.control_evidence)
    print('Invite token (shown once; deliver privately, never through a URL):')
    print(token)
    print('Reissuing the same account ID rotates its token. Removing its entry revokes access.')


if __name__ == '__main__':
    main()
