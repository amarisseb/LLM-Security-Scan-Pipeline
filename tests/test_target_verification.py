"""Offline ownership verification and transport regression tests."""
import io
import os
import socket
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import accounts, target_verification as v

REAL_RESOLVE = v.transport._resolve_public
PUBLIC = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('93.184.216.34', 443))


class VerificationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, ARISEC_SELF_SERVE='1', ARISEC_ACCOUNTS_DB=str(Path(tmp.name) / 'accounts.db'))
        env.start()
        self.addCleanup(env.stop)
        self.owner, _ = accounts.create_guest_session()
        self.other, _ = accounts.create_guest_session()
        app = FastAPI()
        @app.middleware('http')
        async def principal(request, call_next):
            request.state.principal = self.other if request.headers.get('X-Other') else self.owner
            return await call_next(request)
        v.register_verification_routes(app)
        self.client = TestClient(app)
        resolver = patch.object(v.transport, '_resolve_public', return_value=PUBLIC)
        self.resolve = resolver.start()
        self.addCleanup(resolver.stop)

    def challenge(self, url='https://example.com/api'):
        return self.client.post('/verification/challenge', json={'target_url': url})

    def complete(self, challenge, **kwargs):
        return self.client.post('/verification/complete', json={'challenge_id': challenge['challenge_id']}, **kwargs)

    def test_disabled_routes_do_not_authenticate_resolve_or_create_database(self):
        absent = Path(os.environ['ARISEC_ACCOUNTS_DB']).parent / 'disabled' / 'accounts.db'
        legacy = {'id': 'legacy-bearer', 'allowed_origins': []}
        with patch.dict(os.environ, ARISEC_SELF_SERVE='0', ARISEC_ACCOUNTS_DB=str(absent)), patch.object(v, 'principal_for', return_value=legacy) as principal, patch.object(accounts, 'connect_db', side_effect=AssertionError('database touched')) as connect:
            self.assertEqual(self.challenge().status_code, 404)
            self.assertEqual(self.complete({'challenge_id': 'unused'}).status_code, 404)
            principal.assert_not_called()
            connect.assert_not_called()
            self.resolve.assert_not_called()
            self.assertFalse(absent.parent.exists())

    def test_oversized_target_rejected_before_dns_or_database(self):
        with patch.object(accounts, 'connect_db', side_effect=AssertionError('database touched')) as connect:
            for target in ['https://example.com/' + 'a' * 8192, 'x' * 100_000]:
                self.assertEqual(self.challenge(target).status_code, 400)
            connect.assert_not_called()
            self.resolve.assert_not_called()

    def test_grant_origin_uses_callers_transaction(self):
        with closing(accounts.connect_db()) as db:
            db.execute('BEGIN IMMEDIATE')
            accounts.grant_origin(self.owner['id'], 'https://example.com', db=db)
            self.assertTrue(db.in_transaction)
            db.rollback()
            self.assertEqual(db.execute('SELECT count(*) FROM allowed_origins').fetchone()[0], 0)

    def test_success_owner_and_replay(self):
        challenge = self.challenge().json()
        self.assertEqual(challenge['verification_url'], 'https://example.com' + v.WELL_KNOWN)
        self.assertEqual(challenge['expires_in'], 900)
        with patch.object(v, '_fetch_token', return_value=challenge['verification_token'].encode()) as fetch:
            self.assertEqual(self.complete(challenge, headers={'X-Other': '1'}).status_code, 404)
            fetch.assert_not_called()
            self.assertEqual(self.complete(challenge).status_code, 200)
            self.assertEqual(self.complete(challenge).status_code, 404)
            self.assertEqual(fetch.call_count, 1)
        with closing(accounts.connect_db()) as db, db:
            self.assertEqual(db.execute('SELECT origin FROM allowed_origins').fetchone()[0], 'https://example.com')

    def test_expiry_and_expiry_during_fetch(self):
        challenge = self.challenge().json()
        def expire(_):
            with closing(accounts.connect_db()) as db, db:
                db.execute('UPDATE verification_challenges SET expires_at=?', (time.time() - 1,))
            return challenge['verification_token'].encode()
        with patch.object(v, '_fetch_token', side_effect=expire) as fetch:
            self.assertEqual(self.complete(challenge).status_code, 404)
            self.assertEqual(self.complete(challenge).status_code, 404)
            self.assertEqual(fetch.call_count, 1)
        with closing(accounts.connect_db()) as db, db:
            self.assertEqual(db.execute('SELECT count(*) FROM allowed_origins').fetchone()[0], 0)

    def test_bad_token_and_limit(self):
        challenge = self.challenge().json()
        with patch.object(v, '_fetch_token', return_value=b'wrong'):
            self.assertEqual(self.complete(challenge).status_code, 400)
        for _ in range(3):
            self.assertEqual(self.challenge().status_code, 200)
        self.assertEqual(self.challenge().status_code, 429)

    def test_private_and_invalid_urls(self):
        for url in ['http://example.com', 'https://a:b@example.com', 'https://example.com/?',
                    'https://example.com/#x', 'https://localhost', 'https://example.com:22']:
            self.assertEqual(self.challenge(url).status_code, 400, url)
        with patch.object(v.transport.socket, 'getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', 443))]):
            # Restore the actual bounded resolver for a private-address answer.
            self.resolve.side_effect = REAL_RESOLVE
            self.assertEqual(self.challenge('https://127.0.0.1').status_code, 400)

    def test_concurrent_replay(self):
        challenge = self.challenge().json()
        with patch.object(v, '_fetch_token', return_value=challenge['verification_token'].encode()):
            with ThreadPoolExecutor(max_workers=2) as pool:
                statuses = list(pool.map(lambda _: self.complete(challenge).status_code, range(2)))
        self.assertEqual(sorted(statuses), [200, 404])

    def test_grant_failure_rolls_back_consumption(self):
        challenge = self.challenge().json()
        with patch.object(v, '_fetch_token', return_value=challenge['verification_token'].encode()), patch.object(accounts, 'grant_origin', side_effect=RuntimeError('fail')):
            with self.assertRaises(RuntimeError):
                self.complete(challenge)
        with closing(accounts.connect_db()) as db, db:
            self.assertEqual(db.execute('SELECT count(*) FROM verification_challenges').fetchone()[0], 1)

    def test_absolute_deadline_aborts_trickling_fetch(self):
        stopped = threading.Event()
        conn = MagicMock()
        conn.abort.side_effect = stopped.set
        def stall():
            if not stopped.wait(1):
                raise AssertionError('deadline failed to abort connection')
            raise TimeoutError()
        conn.getresponse.side_effect = stall
        started = time.monotonic()
        with patch.object(v, 'REQUEST_TIMEOUT', .05), patch.object(v.transport, '_PinnedHTTPSConnection', return_value=conn):
            with self.assertRaises(v.HTTPException):
                v._fetch_token('https://example.com')
        self.assertTrue(stopped.is_set())
        self.assertLess(time.monotonic() - started, .8)
        conn.close.assert_called_once()

    def test_transport_pinned_exact_path_strips_token_and_rejects_redirect_size(self):
        for status, data, success in [(200, b' token\n', True), (302, b'token', False), (200, b'a' * 4097, False)]:
            conn = MagicMock()
            response = MagicMock(status=status)
            response.getheader.return_value = 'identity'
            stream = io.BytesIO(data)
            response.read1.side_effect = stream.read
            conn.getresponse.return_value = response
            with patch.object(v.transport, '_PinnedHTTPSConnection', return_value=conn) as factory:
                if success:
                    self.assertEqual(v._fetch_token('https://example.com:8443'), b'token')
                else:
                    with self.assertRaises(v.HTTPException):
                        v._fetch_token('https://example.com:8443')
                self.assertEqual(factory.call_args.args[:3], ('example.com', 8443, PUBLIC))
                conn.request.assert_called_once_with('GET', v.WELL_KNOWN, headers={'Accept': 'text/plain', 'Accept-Encoding': 'identity'})
                conn.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
