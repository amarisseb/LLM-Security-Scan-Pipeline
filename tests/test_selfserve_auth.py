"""Self-service tests: isolated temporary SQLite storage, no service calls."""
import asyncio
import hashlib
import importlib.util
import json
import os
import tempfile
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app import accounts, auth_api, security

ORIGIN = 'https://pilot.example'
PASSWORD = 'a long test password 123'


class SelfServeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / 'private' / 'accounts.sqlite3'
        env = patch.dict(os.environ, {'ARISEC_SELF_SERVE': '1', 'ARISEC_ACCOUNTS_DB': str(self.db_path), 'ARISEC_ACCOUNTS_FILE': '', 'ARISEC_LOCAL_DEMO': '0', 'ARISEC_LOCAL_PREVIEW': '0'})
        env.start()
        self.addCleanup(env.stop)
        app = FastAPI()
        app.include_router(auth_api.router)
        self.calls = []

        @app.api_route('/scan', methods=['GET', 'POST'])
        @app.api_route('/verification/challenge', methods=['GET', 'POST'])
        async def protected(request: Request):
            self.calls.append(request.url.path)
            return security.principal_for(request)

        self.app = security.SecurityBoundaryMiddleware(app)
        self.client = TestClient(self.app, base_url=ORIGIN, client=('203.0.113.10', 1234))
        self.addCleanup(self.client.close)

    def guest(self, client=None):
        client = client or self.client
        response = client.get('/account/session')
        self.assertEqual(response.status_code, 200, response.text)
        return accounts.session_principal(client.cookies[accounts.COOKIE_NAME])

    def signup(self, email='person@example.com', password=PASSWORD):
        return self.client.post('/account/signup', json=dict(email=email, password=password), headers={'Origin': ORIGIN})

    def test_guest_cookie_and_promote_same_id(self):
        response = self.client.get('/account/session')
        self.assertEqual(response.json(), dict(authenticated=False, guest=True, email=None, free_scan_available=True))
        cookie = response.headers['set-cookie'].lower()
        for expected in ['httponly', 'secure', 'samesite=lax', 'path=/']:
            self.assertIn(expected, cookie)
        old = self.client.cookies[accounts.COOKIE_NAME]
        guest = accounts.session_principal(old)
        self.assertTrue(accounts.reserve_free_scan(guest, '203.0.113.10', 'guest-scan'))
        self.assertFalse(self.client.get('/account/session').json()['free_scan_available'])
        accounts.grant_origin(guest['id'], 'https://example.com:443')
        response = self.signup(email='Person@Example.com')
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json(), dict(authenticated=True, guest=False, email='person@example.com', free_scan_available=False))
        new = self.client.cookies[accounts.COOKIE_NAME]
        self.assertNotEqual(old, new)
        self.assertIsNone(accounts.session_principal(old))
        principal = accounts.session_principal(new)
        self.assertEqual(principal['id'], guest['id'])
        self.assertEqual(principal['allowed_origins'], ['https://example.com'])
        self.assertFalse(principal['local_demo'])
        other_guest, _ = accounts.create_guest_session()
        self.assertFalse(accounts.reserve_free_scan(other_guest, '203.0.113.99', 'other'))
        self.assertEqual(self.client.get('/scan').json()['id'], guest['id'])
        with closing(accounts.connect_db()) as db:
            row = db.execute('SELECT * FROM accounts WHERE id=?', (guest['id'],)).fetchone()
            self.assertGreaterEqual(len(row['password_salt']), 16)
            self.assertEqual(row['password_hash'], hashlib.pbkdf2_hmac('sha256', PASSWORD.encode(), row['password_salt'], 600000))
            tokens = [r[0] for r in db.execute('SELECT token_sha256 FROM sessions')]
            self.assertNotIn(new, tokens)
            self.assertIn(hashlib.sha256(new.encode()).hexdigest(), tokens)
        raw = self.db_path.read_bytes()
        self.assertNotIn(PASSWORD.encode(), raw)
        self.assertNotIn(new.encode(), raw)

    def test_login_logout_rotation_and_expiry(self):
        self.guest()
        self.assertEqual(self.signup().status_code, 201)
        registered_token = self.client.cookies[accounts.COOKIE_NAME]
        response = self.client.post('/account/logout', headers={'Origin': ORIGIN})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(accounts.session_principal(registered_token))
        self.assertNotIn(accounts.COOKIE_NAME, self.client.cookies)
        self.assertEqual(self.client.get('/scan').status_code, 401)
        old_guest = self.guest()
        guest_token = self.client.cookies[accounts.COOKIE_NAME]
        response = self.client.post('/account/login', json=dict(email='person@example.com', password=PASSWORD), headers={'Origin': ORIGIN})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(accounts.session_principal(guest_token))
        self.assertNotEqual(self.client.get('/scan').json()['id'], old_guest['id'])
        with closing(accounts.connect_db()) as db, db:
            db.execute('UPDATE sessions SET expires_at=0')
        self.assertEqual(self.client.get('/scan').status_code, 401)
        self.assertEqual(self.client.post('/account/login', json=dict(email='person@example.com', password='wrong password long'), headers={'Origin': ORIGIN}).status_code, 401)

    def test_password_limits_generic_errors_and_no_verification_claim(self):
        for password in ['x' * 11, 'x' * 1025, 123, None]:
            with patch.object(accounts, '_password_hash', side_effect=AssertionError('must validate first')):
                response = self.signup(password=password)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), {'detail': 'Invalid credentials.'})
        with patch.object(accounts, '_password_hash', side_effect=AssertionError('must validate first')):
            self.assertEqual(self.signup(email='not an email').status_code, 400)
        self.assertEqual(self.signup(password='x' * 12).status_code, 201)
        self.assertNotIn('verified', self.client.get('/account/session').text)
        # Direct validation covers the upper bound without spending another hash.
        self.assertEqual(len(accounts.validate_credentials('a@example.com', 'x' * 1024)[1]), 1024)

    def test_csrf_tls_and_verification_protection_before_password_hash(self):
        self.guest()
        for path in ['/account/signup', '/account/login', '/account/logout', '/scan', '/verification/challenge']:
            for headers in [{}, {'Origin': 'https://evil.example'}, {'Origin': 'null'}, {'Origin': ORIGIN, 'Sec-Fetch-Site': 'same-site'}, {'Origin': ORIGIN, 'Sec-Fetch-Site': 'cross-site'}]:
                with self.subTest(path=path, headers=headers), patch.object(accounts, '_password_hash', side_effect=AssertionError('hash before CSRF')):
                    self.assertEqual(self.client.post(path, headers=headers, json={}).status_code, 403)
        self.assertFalse(self.calls)
        for path in ['/scan', '/verification/challenge']:
            self.assertEqual(self.client.post(path, headers={'Origin': ORIGIN}).status_code, 200)
        anonymous = TestClient(self.app, base_url=ORIGIN)
        self.addCleanup(anonymous.close)
        self.assertEqual(anonymous.get('/verification/challenge').status_code, 401)
        with TestClient(self.app, base_url='http://pilot.example', client=('127.0.0.1', 1)) as client:
            self.assertEqual(client.get('/account/session').status_code, 403)

    def test_preview_transport_no_identity_or_target_bypass(self):
        with patch.dict(os.environ, {'ARISEC_LOCAL_PREVIEW': '1', 'ARISEC_LOCAL_DEMO': '1'}):
            with TestClient(self.app, base_url='http://127.0.0.1:8000', client=('127.0.0.1', 1)) as client:
                self.assertEqual(client.get('/scan').status_code, 401)
                response = client.get('/account/session')
                self.assertEqual(response.status_code, 200)
                self.assertNotIn('; secure', response.headers['set-cookie'].lower())
                principal = client.get('/scan').json()
                self.assertFalse(principal['local_demo'])
                self.assertTrue(principal['guest'])
                self.assertEqual(principal['allowed_origins'], [])
                for headers in [{'Host': 'evil.example:8000'}, {'Host': 'localhost:9000'}, {'Origin': 'null'}, {'Origin': 'http://evil.example'}, {'Sec-Fetch-Site': 'cross-site'}]:
                    self.assertEqual(client.get('/account/session', headers=headers).status_code, 403)
                self.assertEqual(client.post('/account/logout', headers={'Origin': 'http://127.0.0.1:8000'}).status_code, 200)
            with TestClient(self.app, base_url='http://127.0.0.1:8000', client=('203.0.113.1', 1)) as client:
                self.assertEqual(client.get('/account/session').status_code, 403)

    def test_durable_auth_throttle_before_hash(self):
        for _ in range(10):
            self.assertTrue(accounts.allow_auth_attempt('203.0.113.10'))
        # A separate boundary instance still observes the persisted throttle.
        client = TestClient(security.SecurityBoundaryMiddleware(self.app.app), base_url=ORIGIN, client=('203.0.113.10', 99))
        self.addCleanup(client.close)
        with patch.object(accounts, '_password_hash', side_effect=AssertionError('throttle must run first')):
            for path in ['/account/signup', '/account/login']:
                self.assertEqual(client.post(path, json=dict(email='person@example.com', password=PASSWORD), headers={'Origin': ORIGIN}).status_code, 429)

    def test_request_limit_before_db_and_body_cap(self):
        client = TestClient(security.SecurityBoundaryMiddleware(self.app.app, ip_limit=1), base_url=ORIGIN)
        self.addCleanup(client.close)
        self.assertEqual(client.get('/account/session').status_code, 200)
        with patch.object(accounts, 'session_principal', side_effect=AssertionError('rate must run first')):
            self.assertEqual(client.get('/account/session').status_code, 429)
        with patch.object(accounts, '_password_hash', side_effect=AssertionError('size before hash')):
            response = self.client.post('/account/signup', content=b'x' * (security.MAX_BODY_BYTES + 1), headers={'Origin': ORIGIN, 'Content-Length': '1'})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers['cache-control'], 'no-store')

    def test_quota_atomic_network_durable_and_refund(self):
        guest, _ = accounts.create_guest_session()
        def reserve(i):
            return accounts.reserve_free_scan(guest, '198.51.100.2', f'scan-{i}')
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(reserve, range(6)))
        self.assertEqual(sum(results), 1)
        winner = f'scan-{results.index(True)}'
        other, _ = accounts.create_guest_session()
        self.assertFalse(accounts.reserve_free_scan(other, '198.51.100.200', 'another-cookie'))
        self.assertFalse(accounts.reserve_free_scan(guest, '192.0.2.3', 'another-network'))
        accounts.refund_free_scan(winner)
        accounts.refund_free_scan(winner)
        self.assertTrue(accounts.free_scan_available(guest, '198.51.100.2'))
        self.assertFalse(accounts.reserve_free_scan(guest, '198.51.100.2', winner))
        self.assertTrue(accounts.reserve_free_scan(guest, '198.51.100.2', 'retry'))
        self.assertFalse(accounts.free_scan_available(guest, '198.51.100.2'))
        self.assertFalse(accounts.reserve_free_scan(other, 'invalid', 'invalid-peer'))

    def test_atomic_grant_uses_caller_transaction(self):
        principal, _ = accounts.create_guest_session()
        with closing(accounts.connect_db()) as db:
            db.execute('BEGIN IMMEDIATE')
            accounts.grant_origin(principal['id'], 'https://EXAMPLE.com:443', db=db)
            db.rollback()
            self.assertEqual(db.execute('SELECT COUNT(*) FROM allowed_origins').fetchone()[0], 0)
            accounts.grant_origin(principal['id'], 'https://example.com', db=db)
            db.commit()
        accounts.grant_origin(principal['id'], 'https://example.com')
        with closing(accounts.connect_db()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM allowed_origins').fetchone()[0], 1)

    def test_network_quota_across_distinct_guests_and_ipv6(self):
        guests = [accounts.create_guest_session()[0] for _ in range(4)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda i: accounts.reserve_free_scan(guests[i], '192.0.2.' + str(i + 1), f'network-{i}'), range(4)))
        self.assertEqual(sum(results), 1)
        unused_guest = guests[results.index(False)]
        self.assertTrue(accounts.reserve_free_scan(unused_guest, '2001:db8:1::1', 'ipv6-first'))
        fresh, _ = accounts.create_guest_session()
        self.assertFalse(accounts.reserve_free_scan(fresh, '2001:db8:1::2', 'ipv6-same-network'))
        self.assertEqual(accounts._network_hash('::ffff:192.0.2.1'), accounts._network_hash('192.0.2.1'))

    def test_optional_bearer_and_legacy_default(self):
        token = 'legacy_test_token_abcdefghijklmnopqrstuvwxyz'
        config = Path(self.tmp.name) / 'operator.json'
        config.write_text(json.dumps([dict(id='legacy', email='owner@example.com', token_sha256=hashlib.sha256(token.encode()).hexdigest(), allowed_origins=[])]))
        with patch.dict(os.environ, {'ARISEC_ACCOUNTS_FILE': str(config)}):
            response = self.client.get('/scan', headers={'Authorization': 'Bearer ' + token})
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()['guest'])
        with patch.dict(os.environ, {'ARISEC_SELF_SERVE': '0'}):
            self.assertEqual(self.client.get('/account/session').status_code, 404)
            self.assertEqual(self.client.get('/scan').status_code, 503)

    def test_pilot_only_default_enables_selfserve(self):
        fake_main = types.ModuleType('app.main')
        fake_main.app = FastAPI()
        spec = importlib.util.spec_from_file_location('app._pilot_test', Path(__file__).parents[1] / 'app' / 'pilot.py')
        with patch.dict('sys.modules', {'app.main': fake_main}), patch.dict(os.environ):
            os.environ.pop('ARISEC_SELF_SERVE', None)
            spec.loader.exec_module(importlib.util.module_from_spec(spec))
            self.assertTrue(accounts.enabled())
            self.assertEqual([r.path for r in fake_main.app.routes].count('/account/session'), 0)


class AccountBodyTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_account_and_verification_absolute_timeout_before_handler(self):
        for path in ['/account/signup', '/verification/challenge']:
            sent = []
            async def app(scope, receive, send):
                self.fail('timed-out body reached handler')
            async def receive():
                await asyncio.sleep(1)
                return dict(type='http.request', body=b'', more_body=False)
            async def send(message):
                sent.append(message)
            scope = dict(type='http', scheme='https', method='POST', path=path, client=('203.0.113.10', 1), server=('pilot.example', 443), headers=[(b'host', b'pilot.example'), (b'origin', ORIGIN.encode()), (b'cookie', b'arisec_session=' + b'x' * 43)])
            with patch.dict(os.environ, {'ARISEC_SELF_SERVE': '1'}), patch.object(accounts, 'allow_auth_attempt', return_value=True), patch.object(accounts, 'session_principal', return_value=dict(id='guest', email=None, guest=True, local_demo=False, allowed_origins=[])), patch.object(security, 'BODY_READ_TIMEOUT_SECONDS', 0.02):
                await security.SecurityBoundaryMiddleware(app)(scope, receive, send)
            self.assertEqual(sent[0]['status'], 408)
