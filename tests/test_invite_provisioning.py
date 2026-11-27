import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from tools.manage_pilot import issue_invite


class InviteTests(unittest.TestCase):
    def test_only_digest_is_saved_and_rotation_replaces_existing_account(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'accounts.json'
            first = issue_invite(path, 'alice', 'alice@example.com', ['https://EXAMPLE.com:443'], 'DNS challenge checked')
            self.assertGreaterEqual(len(first), 32)
            entry = json.loads(path.read_text())[0]
            self.assertNotIn(first, path.read_text())
            self.assertEqual(entry['token_sha256'], hashlib.sha256(first.encode()).hexdigest())
            self.assertEqual(entry['allowed_origins'], ['https://example.com'])
            second = issue_invite(path, 'alice', 'alice@example.com', [], 'Provider-key pilot only')
            self.assertNotEqual(first, second)
            self.assertEqual(len(json.loads(path.read_text())), 1)
            self.assertNotIn(first, (path.parent / 'control-approvals.jsonl').read_text())

    def test_grant_rejects_paths_credentials_and_insecure_origins(self):
        with tempfile.TemporaryDirectory() as temp:
            for origin in ['https://example.com/path', 'http://example.com', 'https://user:secret@example.com']:
                with self.assertRaises(ValueError):
                    issue_invite(Path(temp)/'accounts.json', 'alice', 'alice@example.com', [origin], 'checked')
