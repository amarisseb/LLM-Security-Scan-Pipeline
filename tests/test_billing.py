"""Isolated entitlement tests: temporary SQLite only, no payment/network calls."""

import os
import importlib.util
import io
import json
import tempfile
import time
import unittest
from contextlib import closing
from contextlib import redirect_stdout, redirect_stderr
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import accounts, billing
from app.auth_api import router
from app.security import SecurityBoundaryMiddleware


class BillingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {'ARISEC_SELF_SERVE': '1', 'ARISEC_ACCOUNTS_DB': str(Path(self.tmp.name) / 'accounts.sqlite3'), 'ARISEC_ACCOUNTS_FILE': '', 'ARISEC_LOCAL_DEMO': '0', 'ARISEC_LOCAL_PREVIEW': '0'})
        env.start()
        self.addCleanup(env.stop)
        self.guest, self.guest_token = accounts.create_guest_session()
        # Billing fixtures need persisted registered accounts, not repeated
        # password work. Actual signup is covered separately below.
        member, self.member_token = accounts.create_guest_session()
        other, self.other_token = accounts.create_guest_session()
        with closing(accounts.connect_db()) as db, db:
            for principal, email in ((member, 'member@example.com'), (other, 'other@example.com')):
                db.execute('UPDATE accounts SET email=?,password_salt=?,password_hash=? WHERE id=?', (email, b's' * 32, b'h' * 32, principal['id']))
        self.member = accounts.session_principal(self.member_token)
        self.other = accounts.session_principal(self.other_token)

    def client(self, token=None):
        app = FastAPI()
        app.include_router(router)
        billing.register_billing_routes(app)
        client = TestClient(SecurityBoundaryMiddleware(app), base_url='https://pilot.example', client=('203.0.113.1', 1))
        self.addCleanup(client.close)
        if token:
            client.cookies.set(accounts.COOKIE_NAME, token)
        return client

    def test_signup_and_claims_never_grant_paid_access(self):
        new_guest, _ = accounts.create_guest_session()
        promoted, _ = accounts.signup(new_guest, 'signup@example.com', 'long signup password')
        self.assertEqual(promoted['id'], new_guest['id'])
        self.assertEqual(billing.effective_plan(promoted), 'free')
        for principal in (self.member, self.other, self.guest, dict(self.member, plan='team', status='active'), dict(self.guest, guest=False, plan='full')):
            self.assertEqual(billing.effective_plan(principal), 'free')
            self.assertIsNone(billing.require_scan_access(principal, 'free'))
            with self.assertRaises(HTTPException) as error:
                billing.require_scan_access(principal, 'full')
            self.assertEqual(error.exception.status_code, 402)

    def test_active_expired_and_inactive_durable_entitlements(self):
        expiry = time.time() + 3600
        billing.grant_subscription(self.member['id'], 'full', expiry)
        self.assertEqual(billing.effective_plan(self.member), 'full')
        self.assertIsNone(billing.require_scan_access(self.member, 'full'))
        self.assertEqual(billing.effective_plan(self.other), 'free')
        with patch.object(billing.time, 'time', return_value=expiry):
            self.assertEqual(billing.effective_plan(self.member), 'free')
        billing.grant_subscription(self.member['id'], 'team', expiry)
        self.assertEqual(billing.effective_plan(self.member), 'team')
        with closing(accounts.connect_db()) as db, db:
            db.execute("UPDATE subscriptions SET status='past_due' WHERE principal_id=?", (self.member['id'],))
        self.assertEqual(billing.effective_plan(self.member), 'free')
        billing.grant_subscription(self.member['id'], 'full', time.time() - 1)
        self.assertEqual(billing.effective_plan(self.member), 'free')

    def test_guest_cannot_receive_paid_plan(self):
        for principal_id in (self.guest['id'], 'missing'):
            with self.assertRaises(ValueError):
                billing.grant_subscription(principal_id, 'full', time.time() + 3600)
        # Even a database record must not elevate a guest identity.
        with closing(accounts.connect_db()) as db, db:
            billing._initialize(db)
            db.execute("INSERT INTO subscriptions VALUES (?,'team','active',?)", (self.guest['id'], time.time() + 3600))
        self.assertEqual(billing.effective_plan(self.guest), 'free')
        self.assertEqual(billing.effective_plan(dict(self.guest, guest=False)), 'free')

    def test_strict_profiles_and_operator_inputs(self):
        for profile in ('team', 'FULL', '', None, True, ['full']):
            with self.subTest(profile=profile), self.assertRaises(HTTPException) as error:
                billing.require_scan_access(self.member, profile)
            self.assertEqual(error.exception.status_code, 400)
        for expiry in (None, True, '123', float('inf'), float('nan'), -1, 0):
            with self.subTest(expiry=expiry), self.assertRaises(ValueError):
                billing.grant_subscription(self.member['id'], 'full', expiry)
        with self.assertRaises(ValueError):
            billing.grant_subscription(self.member['id'], 'free', time.time() + 3600)

    def test_catalog_is_honest_and_isolated(self):
        catalog = billing.catalog()
        self.assertFalse(catalog['billing_enabled'])
        self.assertEqual([p['id'] for p in catalog['plans']], ['free', 'full', 'team'])
        self.assertEqual([p['name'] for p in catalog['plans']], ['Free', 'Full assessment', 'Bespoke'])
        for tier in catalog['plans'][1:]:
            self.assertEqual(tier['price_label'], 'Quoted after consultation')
            self.assertEqual(tier['cta'], 'Discuss assessment')
        self.assertEqual([p['price'] for p in catalog['plans']], [0, None, None])
        self.assertEqual(catalog['plans'][0]['categories'], ['promptinject'])
        self.assertEqual(catalog['plans'][1]['categories'], ['promptinject', 'dan', 'encoding', 'sysprompt_extraction', 'donotanswer'])
        self.assertEqual(catalog['plans'][2]['categories'], catalog['plans'][1]['categories'])
        self.assertIn('not all garak', catalog['scope_note'])
        self.assertIn('not a compliance audit', catalog['scope_note'])
        catalog['plans'][1]['categories'].append('fake')
        catalog['plans'][0]['price'] = 999
        self.assertNotIn('fake', billing.catalog()['plans'][1]['categories'])
        self.assertEqual(billing.catalog()['plans'][0]['price'], 0)

    def test_public_plans_private_current_plan_and_cross_user(self):
        public = self.client()
        self.assertEqual(public.get('/plans').json(), billing.catalog())
        self.assertEqual(public.get('/account/plan').status_code, 401)
        billing.grant_subscription(self.member['id'], 'team', time.time() + 3600)
        member = self.client(self.member_token)
        self.assertEqual(member.get('/account/plan').json(), dict(plan='team', billing_enabled=False, full_scan_access=True))
        other = self.client(self.other_token)
        response = other.get('/account/plan', params={'principal_id': self.member['id'], 'plan': 'team'})
        self.assertEqual(response.json(), dict(plan='free', billing_enabled=False, full_scan_access=False))
        self.assertEqual(self.client(self.guest_token).get('/account/plan').json()['plan'], 'free')

    def test_no_checkout_or_self_grant_and_disabled_auth(self):
        client = self.client(self.member_token)
        for path in ('/billing/checkout', '/billing/grant', '/subscriptions', '/account/plan'):
            self.assertIn(client.post(path, json=dict(plan='team', principal_id=self.member['id']), headers={'Origin': 'https://pilot.example'}).status_code, (404, 405))
        self.assertEqual(billing.effective_plan(self.member), 'free')
        with patch.dict(os.environ, {'ARISEC_SELF_SERVE': '0'}):
            self.assertEqual(client.get('/account/plan').status_code, 404)
            self.assertEqual(client.get('/plans').status_code, 200)

    def test_storage_failure_fails_closed(self):
        import sqlite3
        with patch.object(accounts, 'connect_db', side_effect=sqlite3.OperationalError('private config')):
            with self.assertRaises(HTTPException) as error:
                billing.require_scan_access(self.member, 'full')
        self.assertEqual(error.exception.status_code, 503)
        self.assertNotIn('private config', error.exception.detail)

    def test_consultation_registered_only_stored_not_paid(self):
        self.assertEqual(self.client().post('/account/consultation', json={}, headers={'Origin': 'https://pilot.example'}).status_code, 401)
        guest = self.client(self.guest_token)
        self.assertEqual(guest.post('/account/consultation', json={}, headers={'Origin': 'https://pilot.example'}).status_code, 403)
        self.assertEqual(guest.get('/account/consultation').status_code, 403)
        client = self.client(self.member_token)
        self.assertEqual(client.get('/account/consultation').json(), dict(request_id=None, status='not_requested'))
        response = client.post('/account/consultation', json={'message': 'Please discuss scope.'}, headers={'Origin': 'https://pilot.example'})
        self.assertEqual(response.status_code, 201, response.text)
        body = response.json()
        self.assertEqual(set(body), {'request_id', 'status'})
        self.assertEqual(body['status'], 'requested')
        self.assertEqual(client.get('/account/consultation').json(), body)
        self.assertEqual(billing.effective_plan(self.member), 'free')
        with closing(accounts.connect_db()) as db:
            row = db.execute('SELECT * FROM consultations WHERE id=?', (body['request_id'],)).fetchone()
            self.assertEqual(row['principal_id'], self.member['id'])
            self.assertEqual(row['email_snapshot'], 'member@example.com')
            self.assertEqual(row['message'], 'Please discuss scope.')
        other = self.client(self.other_token)
        self.assertEqual(other.get('/account/consultation', params={'principal_id': self.member['id'], 'request_id': body['request_id']}).json(), dict(request_id=None, status='not_requested'))
        self.assertEqual(other.get('/account/consultation/' + body['request_id']).status_code, 404)

    def test_consultation_csrf_body_validation_and_limits(self):
        client = self.client(self.member_token)
        for headers in ({}, {'Origin': 'null'}, {'Origin': 'https://evil.example'}, {'Origin': 'https://pilot.example', 'Sec-Fetch-Site': 'cross-site'}):
            self.assertEqual(client.post('/account/consultation', json={}, headers=headers).status_code, 403)
        origin = {'Origin': 'https://pilot.example'}
        for body in ({'message': 'x' * 2001}, {'message': 123}, {'message': None}, {'message': '', 'email': 'attacker@example.com'}, {'principal_id': self.other['id']}, []):
            response = client.post('/account/consultation', json=body, headers=origin)
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json(), {'detail': 'Invalid consultation request.'})
        self.assertEqual(client.post('/account/consultation', content=b'x' * (128 * 1024 + 1), headers=origin).status_code, 413)
        # Missing message is a valid blank request; max-length boundary is valid too.
        self.assertEqual(client.post('/account/consultation', json={}, headers=origin).status_code, 201)
        other = self.client(self.other_token)
        self.assertEqual(other.post('/account/consultation', json={'message': 'x' * 2000}, headers=origin).status_code, 201)

    def test_consultation_rate_durable_rolling_window_and_atomic(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            def request(_):
                try:
                    return billing._request_consultation(self.member, '')['status']
                except HTTPException as error:
                    return error.status_code
            outcomes = list(pool.map(request, range(4)))
        self.assertEqual(outcomes.count('requested'), 1)
        self.assertEqual(outcomes.count(429), 3)
        with closing(accounts.connect_db()) as db:
            created = db.execute('SELECT created_at FROM consultations WHERE principal_id=?', (self.member['id'],)).fetchone()[0]
        with patch.object(billing.time, 'time', return_value=created + 86399):
            with self.assertRaises(HTTPException) as error:
                billing._request_consultation(self.member, '')
            self.assertEqual(error.exception.status_code, 429)
        with patch.object(billing.time, 'time', return_value=created + 86400):
            self.assertEqual(billing._request_consultation(self.member, '')['status'], 'requested')
        self.assertEqual(billing._request_consultation(self.other, '')['status'], 'requested')

    def test_consultation_storage_failure_is_generic(self):
        import sqlite3
        with patch.object(accounts, 'connect_db', side_effect=sqlite3.OperationalError('private details')):
            with self.assertRaises(HTTPException) as error:
                billing._request_consultation(self.member, '')
        self.assertEqual(error.exception.status_code, 503)
        self.assertNotIn('private', error.exception.detail)

    def test_operator_cli_is_read_only_and_escapes_untrusted_messages(self):
        billing._request_consultation(self.member, 'test\x1b[31m')
        path = Path(os.environ['ARISEC_ACCOUNTS_DB'])
        original = path.read_bytes()
        spec = importlib.util.spec_from_file_location('manage_consultations', Path(__file__).parents[1] / 'tools' / 'manage_consultations.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        output = io.StringIO()
        with redirect_stdout(output), patch.object(cli.sqlite3, 'connect', wraps=cli.sqlite3.connect) as connect:
            self.assertEqual(cli.main(['--db', str(path), '--limit', '1']), 0)
        self.assertTrue(connect.call_args.args[0].endswith('?mode=ro'))
        self.assertTrue(connect.call_args.kwargs['uri'])
        self.assertNotIn('\x1b', output.getvalue())
        rows = json.loads(output.getvalue())
        self.assertEqual(rows[0]['email'], 'member@example.com')
        self.assertEqual(rows[0]['message'], 'test\x1b[31m')
        self.assertEqual(path.read_bytes(), original)
        missing = path.parent / 'does-not-exist.sqlite3'
        with redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['--db', str(missing)]), 1)
        self.assertFalse(missing.exists())


if __name__ == '__main__':
    unittest.main()
