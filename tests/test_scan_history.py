"""Owner history against temporary storage, without lifespan/retention or workers."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import accounts, main, scan_store


class ScanHistoryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, {
            'ARISEC_SELF_SERVE': '1', 'ARISEC_LOCAL_DEMO': '0',
            'ARISEC_LOCAL_PREVIEW': '0', 'ARISEC_ACCOUNTS_FILE': '',
            'ARISEC_ACCOUNTS_DB': str(Path(tmp.name) / 'accounts.sqlite3'),
        })
        env.start()
        self.addCleanup(env.stop)
        self.store = scan_store.ScanStore(Path(tmp.name) / 'scans')
        replacement = patch.object(main, 'store', self.store)
        replacement.start()
        self.addCleanup(replacement.stop)
        self.client = self.new_client()
        self.owner, token = accounts.create_guest_session()
        self.client.cookies.set(accounts.COOKIE_NAME, token)

    def new_client(self):
        client = TestClient(main.app, base_url='https://pilot.example')
        self.addCleanup(client.close)
        return client

    def create(self, number, owner=None, **fields):
        sid = f'{number:032x}'
        self.store.create(sid, 'https://example.com/private?key=SECRET',
                          owner_id=owner or self.owner['id'])
        self.store.update(sid, created_at=f'2026-11-{number:02d}T12:00:00+00:00', **fields)
        return sid

    def test_guest_own_and_cross_owner_isolation(self):
        own = self.create(1)
        other, token = accounts.create_guest_session()
        foreign = self.create(2, other['id'])
        self.create(3, 'legacy-owner')
        self.store.update(f'{3:032x}', owner_id=None)
        response = self.client.get('/account/scans', params={'owner_id': other['id'], 'scan_id': foreign})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([r['scan_id'] for r in response.json()['scans']], [own])
        self.assertEqual(response.headers['cache-control'], 'no-store')
        second = self.new_client()
        second.cookies.set(accounts.COOKIE_NAME, token)
        self.assertEqual([r['scan_id'] for r in second.get('/account/scans').json()['scans']], [foreign])

    def test_authenticated_own(self):
        principal, token = accounts.signup(None, 'history@example.com', 'long-test-password-123')
        self.client.cookies.set(accounts.COOKIE_NAME, token)
        sid = self.create(1, principal['id'])
        self.create(2)
        self.assertEqual([r['scan_id'] for r in self.client.get('/account/scans').json()['scans']], [sid])

    def test_no_secrets_paths_or_report_reads(self):
        sid = self.create(1, api_key='SECRET', report_file='/private/report.jsonl',
                          progress={'response': 'SECRET'}, error_code='SECRET')
        self.store.update(sid, target_url='https://user:SECRET@example.com/private/SECRET?key=SECRET#SECRET')
        with patch.object(self.store, 'report_path', side_effect=AssertionError('report read')):
            response = self.client.get('/account/scans')
        self.assertEqual(response.json(), {'scans': [{
            'scan_id': sid, 'status': 'queued', 'target': 'https://example.com',
            'created_at': '2026-11-01T12:00:00+00:00',
        }]})
        self.assertNotIn('SECRET', response.text)
        self.assertNotIn('/private', response.text)

    def test_cap_newest_twenty_and_skip_malformed(self):
        for number in range(1, 26):
            self.create(number)
        self.create(26, created_marker='ignored')
        self.store.update(f'{26:032x}', created_at='invalid')
        self.create(27)
        self.store.update(f'{27:032x}', status='SECRET')
        self.create(28)
        (self.store.scan_dir(f'{28:032x}') / 'status.json').write_text('{broken')
        rows = self.client.get('/account/scans').json()['scans']
        self.assertEqual([r['scan_id'] for r in rows], [f'{n:032x}' for n in range(25, 5, -1)])
        self.assertTrue(all(set(r) == {'scan_id', 'status', 'target', 'created_at'} for r in rows))

    def test_missing_session_and_disabled_fail_closed(self):
        self.create(1)
        self.assertEqual(self.new_client().get('/account/scans').status_code, 401)
        with patch.dict(os.environ, {'ARISEC_SELF_SERVE': '0', 'ARISEC_LOCAL_DEMO': '1'}):
            self.assertEqual(self.client.get('/account/scans').status_code, 404)

    def test_empty_and_invalid_target(self):
        self.assertEqual(self.client.get('/account/scans').json(), {'scans': []})
        sid = self.create(1)
        for target in ('/private/SECRET', 'https://example.com:invalid/private', None):
            self.store.update(sid, target_url=target)
            self.assertEqual(self.client.get('/account/scans').json()['scans'][0]['target'], 'AI feature')


if __name__ == '__main__':
    unittest.main()
