"""Run backend tests with isolated storage and filtered environment variables."""
import argparse
import contextlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pattern", default="test_*.py")
    args = parser.parse_args()
    allowed = {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "SYSTEMDRIVE",
               "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
               "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "LANG", "LC_ALL", "TZ"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    os.environ.clear()
    os.environ.update(environment)
    with tempfile.TemporaryDirectory(prefix="arisec-checks-") as temporary:
        folder = Path(temporary).resolve()
        os.environ.update(ARISEC_LOCAL_DEMO="0", ARISEC_LOCAL_PREVIEW="0", ARISEC_LOCAL_ASSURANCE="0",
                          ARISEC_SELF_SERVE="0", ARISEC_ACCOUNTS_DB=str(folder / "accounts.sqlite3"),
                          SCAN_OUTPUT_DIR=str(folder / "runs"), ATTESTATION_LOG_PATH=str(folder / "attestations.jsonl"),
                          PYTHON_DOTENV_DISABLED="1", LANGSMITH_TRACING="false", OTEL_SDK_DISABLED="true")
        os.environ['GARAK_LOG_FILE'] = os.devnull
        output = sys.stderr
        # Engine/probe chatter is not a result. Keep unittest failures visible.
        with open(os.devnull, "w", encoding="utf-8") as quiet, contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
            suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern=args.pattern)
            if suite.countTestCases() == 0:
                print(f"ERROR: No tests discovered for pattern {args.pattern!r}.", file=output)
                return 1
            result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
