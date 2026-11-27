"""Read-only operator listing; does not send messages or grant entitlements.

Run from the repository root: python tools/manage_consultations.py --limit 100
Uses ARISEC_ACCOUNTS_DB or --db; keep output private because it contains emails
and user-supplied messages. JSON escaping prevents terminal control injection.
"""

import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(description="List stored consultation requests (read-only).")
    parser.add_argument("--db", default=os.getenv("ARISEC_ACCOUNTS_DB", ".arisec-private/accounts.sqlite3"))
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 1000:
        parser.error("--limit must be between 1 and 1000")
    try:
        # SQLite mode=ro refuses creation and writes, even if this script changes.
        db = sqlite3.connect(Path(args.db).resolve().as_uri() + "?mode=ro", uri=True)
        try:
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT id AS request_id,email_snapshot AS email,message,created_at FROM consultations ORDER BY created_at DESC,id DESC LIMIT ?", (args.limit,)).fetchall()
            print(json.dumps([dict(row) for row in rows], ensure_ascii=True, indent=2))
        finally:
            db.close()
    except (OSError, sqlite3.Error):
        print("Consultation storage is unavailable.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
