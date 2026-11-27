import asyncio
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.security import SecurityBoundaryMiddleware, principal_for, local_demo_allowed, MAX_BODY_BYTES

TOKEN = 'test_fixture_0123456789abcdefghijklmnop'
AUTH = {'Authorization': 'Bearer ' + TOKEN}


class SecurityBoundaryTests(unittest.TestCase):
    def test_cors_preflight_is_allowed_without_exempting_actual_reads(self):
        from fastapi.middleware.cors import CORSMiddleware
        wrapped = SecurityBoundaryMiddleware(CORSMiddleware(self.app,
            allow_origins=['https://frontend.example'], allow_methods=['GET', 'POST'],
            allow_headers=['Authorization', 'Content-Type']))
        client = TestClient(wrapped, base_url='https://testserver')
        response = client.options('/scan', headers={'Origin':'https://frontend.example',
            'Access-Control-Request-Method':'POST', 'Access-Control-Request-Headers':'authorization,content-type'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.get('/scan', headers={'Origin':'https://frontend.example'}).status_code, 401)
        self.assertFalse(self.calls)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'accounts.json'
        self.account = dict(id='pilot', email='pilot@example.com', token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest(), allowed_origins=['https://example.com'])
        self.write([self.account])
        env = patch.dict(os.environ, {'ARISEC_ACCOUNTS_FILE': str(self.path), 'ARISEC_LOCAL_DEMO': '0'})
        env.start()
        self.addCleanup(env.stop)
        self.calls = []
        self.app = FastAPI()

        @self.app.api_route('/scan', methods=['GET', 'POST'])
        @self.app.get('/scan/{scan_id}')
        async def scan(request: Request):
            self.calls.append(True)
            return dict(principal=principal_for(request), demo=local_demo_allowed(request), size=len(await request.body()))

    def write(self, entries):
        self.path.write_text(json.dumps(entries), encoding='utf-8')

    def client(self, **kwargs):
        return TestClient(SecurityBoundaryMiddleware(self.app, **kwargs), base_url='https://testserver')

    def test_authentication_all_routes_and_identity(self):
        client = self.client()
        for path in ['/scan', '/scan/abc', '/scan/abc/report']:
            self.assertEqual(client.get(path).status_code, 401)
        for token in ['Bearer wrong', 'Basic secret', 'Bearer secret extra']:
            self.assertEqual(client.get('/scan', headers={'Authorization': token}).status_code, 401)
        response = client.get('/scan/abc', headers=AUTH)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['principal'], dict(id='pilot', email='pilot@example.com', allowed_origins=['https://example.com'], local_demo=False))
        self.assertNotIn('token_sha256', response.text)

    def test_fail_closed_and_reload(self):
        client = self.client()
        for config in [[], {}, [dict(self.account, token='plaintext')], [dict(self.account, token_sha256='bad')], [dict(self.account, allowed_origins=['https://x/#fragment'])]]:
            self.write(config)
            self.assertEqual(client.get('/scan', headers=AUTH).status_code, 503)
        self.path.write_text('{')
        self.assertEqual(client.get('/scan').status_code, 503)
        self.path.unlink()
        self.assertEqual(client.get('/scan').status_code, 503)
        self.write([self.account])
        self.assertEqual(client.get('/scan', headers=AUTH).status_code, 200)
        self.write([dict(self.account, token_sha256=hashlib.sha256(b'new').hexdigest())])
        self.assertEqual(client.get('/scan', headers=AUTH).status_code, 401)
        with patch.dict(os.environ, {'ARISEC_ACCOUNTS_FILE': ''}):
            self.assertEqual(client.get('/scan').status_code, 503)

    def test_tls_and_demo_are_server_controlled(self):
        app = SecurityBoundaryMiddleware(self.app)
        with TestClient(app, base_url='http://127.0.0.1:8000', client=('127.0.0.1', 123)) as client:
            self.assertEqual(client.get('/scan?ARISEC_LOCAL_DEMO=1', headers=AUTH).status_code, 403)
            with patch.dict(os.environ, {'ARISEC_LOCAL_DEMO': '1'}):
                response = client.get('/scan')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['principal']['id'], 'local-demo')
                self.assertEqual(response.json()['principal']['allowed_origins'], [])
        with patch.dict(os.environ, {'ARISEC_LOCAL_DEMO': '1'}):
            with TestClient(app, base_url='http://127.0.0.1:8000', client=('203.0.113.1', 123)) as client:
                self.assertEqual(client.get('/scan', headers={'X-Forwarded-For': '127.0.0.1', 'X-Forwarded-Proto': 'https'}).status_code, 403)

    def test_rate_limits_before_app(self):
        client = self.client(ip_limit=1)
        self.assertEqual(client.get('/scan').status_code, 401)
        self.assertEqual(client.get('/scan', headers=AUTH).status_code, 429)
        self.assertEqual(self.calls, [])
        client = self.client(principal_limit=1)
        self.assertEqual(client.get('/scan', headers=AUTH).status_code, 200)
        self.assertEqual(client.get('/scan', headers=AUTH).status_code, 429)

    def test_demo_rejects_rebinding_and_cross_origin_requests(self):
        with patch.dict(os.environ, {'ARISEC_LOCAL_DEMO': '1'}):
            with TestClient(SecurityBoundaryMiddleware(self.app), base_url='http://127.0.0.1:8000', client=('127.0.0.1', 123)) as client:
                attacks = [
                    {'Host': 'attacker.example:8000'},
                    {'Host': '127.0.0.1:9000'},
                    {'Host': '127.0.0.1'},
                    {'Origin': 'https://evil.example'},
                    {'Origin': 'null'},
                    {'Origin': 'http://localhost:8000'},
                    {'Origin': 'http://127.0.0.1:9000'},
                    {'Origin': 'https://127.0.0.1:8000'},
                    {'Sec-Fetch-Site': 'cross-site'},
                    {'Sec-Fetch-Site': 'same-site'},
                    [('Host', '127.0.0.1:8000'), ('Host', '127.0.0.1:8000')],
                    [('Origin', 'http://127.0.0.1:8000'), ('Origin', 'http://127.0.0.1:8000')],
                    {'Host': 'attacker.example:8000', 'X-Forwarded-Host': '127.0.0.1:8000'},
                ]
                for headers in attacks:
                    with self.subTest(headers=headers):
                        self.assertEqual(client.get('/scan', headers=headers).status_code, 403)
                        self.assertEqual(client.get('/security-config', headers=headers).json(), dict(authentication_required=True, web_scanning_available=False))
                self.assertFalse(self.calls)
                for headers in [{}, {'Origin': 'http://127.0.0.1:8000', 'Sec-Fetch-Site': 'same-origin'}, {'Sec-Fetch-Site': 'none'}]:
                    self.assertEqual(client.get('/scan', headers=headers).status_code, 200)

    def test_demo_authority_validation_without_dns(self):
        from app.security import _demo
        scope = dict(scheme='http', client=('127.0.0.1', 123), server=('0.0.0.0', 8000))
        with patch.dict(os.environ, {'ARISEC_LOCAL_DEMO': '1'}), patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')):
            for host in [b'localhost:8000', b'127.0.0.1:8000', b'[::1]:8000']:
                self.assertTrue(_demo(dict(scope, headers=[(b'host', host)])))
            for host in [b'localhost.evil:8000', b'2130706433:8000', b'127.1:8000', b'127.0.0.1:8000/', b'user@localhost:8000', b'localhost:8000#', b'localhost:8000?', b'localhost:8001']:
                self.assertFalse(_demo(dict(scope, headers=[(b'host', host)])))
            self.assertFalse(_demo(dict(scope, headers=[])))
            self.assertFalse(_demo(dict(scope, server=None, headers=[(b'host', b'localhost:8000')])))
            self.assertTrue(_demo(dict(scope, server=('127.0.0.1', 80), headers=[(b'host', b'localhost'), (b'origin', b'http://localhost:80')])))

    def test_body_limit_and_headers(self):
        client = self.client()
        headers = AUTH
        self.assertEqual(client.post('/scan', content=b'x' * MAX_BODY_BYTES, headers=headers).status_code, 200)
        response = client.post('/scan', content=b'x' * (MAX_BODY_BYTES + 1), headers=headers)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(response.headers['referrer-policy'], 'no-referrer')
        self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
        self.assertIn('max-age', response.headers['strict-transport-security'])
        self.assertNotIn('content-security-policy', response.headers)

    def test_safe_public_metadata(self):
        response = self.client().get('/security-config')
        self.assertEqual(response.json(), dict(authentication_required=True, web_scanning_available=False))
        self.path.unlink()
        self.assertEqual(self.client().get('/security-config').json()['web_scanning_available'], False)
        with patch.dict(os.environ, {'ARISEC_LOCAL_DEMO': '1'}):
            with TestClient(SecurityBoundaryMiddleware(self.app), base_url='http://127.0.0.1:8000', client=('127.0.0.1', 123)) as client:
                self.assertEqual(client.get('/security-config').json(), dict(authentication_required=False, web_scanning_available=True))
            self.assertEqual(self.client().get('/security-config').json()['web_scanning_available'], False)

    def test_short_and_non_urlsafe_tokens_rejected_even_when_hash_matches(self):
        client = self.client()
        for token in ['x' * 31, 'x' * 31 + '+', 'x' * 31 + '/', 'x' * 31 + '=']:
            self.write([dict(self.account, token_sha256=hashlib.sha256(token.encode()).hexdigest())])
            self.assertEqual(client.get('/scan', headers={'Authorization': 'Bearer ' + token}).status_code, 401)
        token = 'x' * 32
        self.write([dict(self.account, token_sha256=hashlib.sha256(token.encode()).hexdigest())])
        self.assertEqual(client.get('/scan', headers={'Authorization': 'Bearer ' + token}).status_code, 200)


class ChunkedTests(unittest.IsolatedAsyncioTestCase):
    async def test_absolute_deadline_for_stalled_and_trickling_bodies(self):
        from app import security
        for trickle in (False, True):
            with self.subTest(trickle=trickle):
                calls, sent, reads = [], [], []

                async def app(scope, receive, send):
                    calls.append(True)

                async def send(message):
                    sent.append(message)

                async def receive():
                    reads.append(True)
                    await asyncio.sleep(0.02 if trickle else 1)
                    return dict(type='http.request', body=b'x', more_body=len(reads) < 10)

                scope = dict(type='http', scheme='https', path='/scan', method='POST', client=('127.0.0.1', 1), server=('127.0.0.1', 8000), headers=[(b'host', b'127.0.0.1:8000')])
                with patch.dict(os.environ, {'ARISEC_LOCAL_DEMO': '1'}), patch.object(security, 'BODY_READ_TIMEOUT_SECONDS', 0.05):
                    await security.SecurityBoundaryMiddleware(app)(scope, receive, send)
                self.assertEqual(sent[0]['status'], 408)
                self.assertEqual(json.loads(sent[1]['body']), {'detail': 'Request timed out.'})
                self.assertIn((b'cache-control', b'no-store'), sent[0]['headers'])
                self.assertFalse(calls)
                self.assertLess(len(reads), 10)

    async def test_raw_chunked_limit_ignores_content_length(self):
        from app import security
        calls, sent = [], []
        async def app(scope, receive, send):
            calls.append(True)
        async def send(message):
            sent.append(message)
        chunks = iter([dict(type='http.request', body=b'x' * 65536, more_body=True), dict(type='http.request', body=b'x' * 65536, more_body=True), dict(type='http.request', body=b'x', more_body=False)])
        async def receive():
            return next(chunks)
        scope = dict(type='http', scheme='https', path='/scan', method='POST', client=('127.0.0.1', 1), server=('127.0.0.1', 8000), headers=[(b'host', b'127.0.0.1:8000'), (b'content-length', b'1')])
        with patch.dict(os.environ, {'ARISEC_LOCAL_DEMO': '1'}):
            await security.SecurityBoundaryMiddleware(app)(scope, receive, send)
        self.assertEqual(sent[0]['status'], 413)
        self.assertFalse(calls)
