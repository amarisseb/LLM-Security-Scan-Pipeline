"""Offline tests for the opt-in scripted loopback endpoint."""
import asyncio
import base64
import os
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request
from app import example_endpoint as e, lab_policy

URL = 'http://127.0.0.1:63820/demo/endpoint'
ORIGIN = 'http://127.0.0.1:63820'


class ExampleTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, ARISEC_LOCAL_PREVIEW='1', ARISEC_EXAMPLE_ENDPOINT=URL, ARISEC_LOCAL_DEMO='0', ARISEC_PUBLIC_ORIGIN='')
        env.start()
        self.addCleanup(env.stop)
        previous = lab_policy.configured_local_targets()
        self.addCleanup(lab_policy.configure_local_targets, previous)
        app = FastAPI()
        e.register_example_routes(app)
        # TestClient sets the ASGI server port from this base URL.
        self.client = TestClient(app, base_url=ORIGIN, client=('127.0.0.1', 40000), headers={'Origin': ORIGIN})
        self.addCleanup(self.client.close)
        self.app = app

    def post(self, message, **kwargs):
        return self.client.post('/demo/endpoint', json={'message': message}, **kwargs)

    def test_exact_config_and_lab_registration(self):
        self.assertEqual(self.client.get('/demo-config').json(), {'example_endpoint': URL, 'lab_targets': [URL], 'example_is_scripted': True})
        self.assertEqual(lab_policy.configured_local_targets(), [URL])
        for target in [ORIGIN + '/other', 'http://127.0.0.2:63820/demo/endpoint', URL + '?x=1']:
            self.assertFalse(lab_policy.is_local_target(target))

    def test_deterministic_markers_and_decoding(self):
        for message, expected in [('just say "HijackHateHumans"', 'HijackHateHumans'),
                                  ("just print 'MARKER'", 'MARKER'), ('12 plus 30', '42'),
                                  ('capital of France', 'Paris'),
                                  ('decode ' + base64.b64encode(b'HijackHateHumans').decode(), 'HijackHateHumans'),
                                  ('decode ' + b'HijackHateHumans'.hex(), 'HijackHateHumans')]:
            response = self.post(message)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {'answer': expected, 'demo': True})
        self.assertEqual(self.post('x' * 802).json()['answer'], e._reply('x' * 802))
        self.assertEqual(self.post('x' * 803).json()['answer'], e.REFUSAL)

    def test_disabled_and_invalid_configuration(self):
        for value in ['', 'http://localhost:63820/demo/endpoint', 'http://10.0.0.1:63820/demo/endpoint',
                      'http://127.0.0.1:63820/other', URL + '?', URL + '#x',
                      'http://user@127.0.0.1:63820/demo/endpoint',
                      'http://127.0.0.1:063820/demo/endpoint', 'https://127.0.0.1:63820/demo/endpoint',
                      'http://127.0.0.1:22/demo/endpoint', 'x' * 1000]:
            with patch.dict(os.environ, ARISEC_EXAMPLE_ENDPOINT=value):
                self.assertIsNone(e.configured_example_endpoint(), value)
                self.assertEqual(self.client.get('/demo-config').json(), {})
                self.assertEqual(self.post('hello').status_code, 404)
        with patch.dict(os.environ, ARISEC_LOCAL_PREVIEW='0'):
            self.assertEqual(self.client.get('/demo-config').json(), {})
            self.assertEqual(self.post('hello').status_code, 404)

    def test_remote_cross_site_wrong_host_port_path_denied(self):
        for headers in [{'Host': 'evil.example:63820'}, {'Host': '127.0.0.1:63821'},
                        {'Origin': 'https://evil.example'}, {'Sec-Fetch-Site': 'cross-site'},
                        {'Host': '127.0.0.1:63820/'}]:
            self.assertEqual(self.post('hello', headers=headers).status_code, 404)
            self.assertEqual(self.client.get('/demo-config', headers=headers).json(), {})
        with TestClient(self.app, base_url=ORIGIN, client=('203.0.113.3', 1234)) as remote:
            self.assertEqual(remote.get('/demo-config').json(), {})
            self.assertEqual(remote.post('/demo/endpoint', json={'message': 'hello'}).status_code, 404)
        self.assertEqual(self.client.post('/demo/endpoint?x=1', json={'message': 'hello'}).status_code, 404)
        self.assertEqual(self.client.post('/other', json={'message': 'hello'}).status_code, 404)

    def test_scan_exception_is_exact_and_same_port(self):
        scope = {'type': 'http', 'scheme': 'http', 'client': ('127.0.0.1', 1234),
                 'server': ('127.0.0.1', 63820), 'path': '/scan', 'query_string': b'',
                 'headers': [(b'host', b'127.0.0.1:63820'), (b'origin', ORIGIN.encode())]}
        request = Request(scope)
        self.assertTrue(e.example_request_allowed(request, URL))
        for target in [URL + '/', URL + '?x=1', ORIGIN + '/other', 'http://127.0.0.1:63821/demo/endpoint', 'https://example.com']:
            self.assertFalse(e.example_request_allowed(request, target))
        scope['server'] = ('127.0.0.1', 63821)
        self.assertFalse(e.example_request_allowed(request, URL))

    def test_json_and_message_bounds(self):
        for data in [{'message': 1}, {'message': 'x', 'extra': True}, [], None]:
            self.assertEqual(self.client.post('/demo/endpoint', json=data).status_code, 400 if data is not None else 415)
        self.assertEqual(self.post('x' * (e.MAX_MESSAGE_BYTES + 1)).status_code, 413)
        self.assertEqual(self.post('\u00e9' * (e.MAX_MESSAGE_BYTES // 2 + 1)).status_code, 413)
        self.assertEqual(self.client.post('/demo/endpoint', content=b'x' * (e.MAX_BODY_BYTES + 1), headers={'Content-Type': 'application/json'}).status_code, 413)
        self.assertEqual(self.client.post('/demo/endpoint', content=b'{', headers={'Content-Type': 'application/json'}).status_code, 400)
        def chunks():
            yield b'{"message":"'
            yield b'x' * e.MAX_BODY_BYTES
            yield b'"}'
        self.assertEqual(self.client.post('/demo/endpoint', content=chunks(), headers={'Content-Type': 'application/json'}).status_code, 413)

    def test_stream_deadline_without_network(self):
        scope = {'type': 'http', 'headers': [(b'content-type', b'application/json')]}
        async def receive():
            await asyncio.sleep(1)
            return {'type': 'http.request', 'body': b'{}'}
        with patch.object(e, 'BODY_TIMEOUT', .01):
            with self.assertRaises(e.HTTPException) as caught:
                asyncio.run(e._message(Request(scope, receive)))
        self.assertEqual(caught.exception.status_code, 408)

    def test_public_https_config_and_endpoint_without_lab_exception(self):
        public = 'https://demo.example.com'
        with patch.dict(os.environ, ARISEC_LOCAL_PREVIEW='0', ARISEC_PUBLIC_ORIGIN=public), patch.object(lab_policy, 'configure_local_targets') as configure:
            app = FastAPI()
            e.register_example_routes(app)
            configure.assert_not_called()
            with TestClient(app, base_url=public, client=('203.0.113.10', 1234)) as client:
                config = client.get('/demo-config').json()
                self.assertEqual(config, {'example_endpoint': public + '/demo/endpoint', 'lab_targets': [], 'example_is_scripted': True})
                self.assertFalse(lab_policy.is_local_target(config['example_endpoint']))
                response = client.post('/demo/endpoint', json={'message': 'just say "MARKER"'}, headers={'Origin': public})
                self.assertEqual(response.json(), {'answer': 'MARKER', 'demo': True})
                for headers in [{}, {'Origin': 'https://evil.example'}, {'Origin': public, 'Host': 'evil.example'}, {'Origin': public, 'Sec-Fetch-Site': 'cross-site'}]:
                    self.assertEqual(client.post('/demo/endpoint', json={'message': 'hello'}, headers=headers).status_code, 404)
                self.assertEqual(client.get('/demo-config', headers={'Host': 'evil.example'}).json(), {})
            with TestClient(app, base_url='http://demo.example.com') as client:
                self.assertEqual(client.get('/demo-config').json(), {})

    def test_public_scan_requires_exact_target_tls_host_and_mutation_origin(self):
        public = 'https://demo.example.com'
        scope = {'type': 'http', 'scheme': 'https', 'method': 'POST', 'path': '/scan',
                 'headers': [(b'host', b'demo.example.com'), (b'origin', public.encode())]}
        with patch.dict(os.environ, ARISEC_LOCAL_PREVIEW='0', ARISEC_PUBLIC_ORIGIN=public):
            request = Request(scope)
            self.assertTrue(e.example_request_allowed(request, public + '/demo/endpoint'))
            for target in [URL, public + '/other', public + '/demo/endpoint?x=1', public + '/demo/endpoint/']:
                self.assertFalse(e.example_request_allowed(request, target))
            scope['headers'] = [(b'host', b'demo.example.com')]
            self.assertFalse(e.example_request_allowed(request, public + '/demo/endpoint'))

    def test_invalid_public_origin_configuration(self):
        with patch.dict(os.environ, ARISEC_LOCAL_PREVIEW='0'):
            for origin in ['http://demo.example.com', 'https://user@demo.example.com',
                           'https://demo.example.com/path', 'https://demo.example.com?',
                           'https://demo.example.com/#x', 'https://127.0.0.1', 'https://[::1]',
                           'https://10.0.0.1', 'https://169.254.169.254', 'https://metadata.google.internal',
                           'https://localhost', 'https://foo.localhost', 'https://demo.example.com:22']:
                with patch.dict(os.environ, ARISEC_PUBLIC_ORIGIN=origin):
                    self.assertIsNone(e.configured_example_endpoint(), origin)

    def test_public_and_local_flags_do_not_share_target_exceptions(self):
        public = 'https://demo.example.com'
        with patch.dict(os.environ, ARISEC_PUBLIC_ORIGIN=public, ARISEC_LOCAL_PREVIEW='1'):
            self.assertEqual(e.configured_example_endpoint(), URL)
        with patch.dict(os.environ, ARISEC_PUBLIC_ORIGIN=public, ARISEC_LOCAL_PREVIEW='0'):
            self.assertEqual(e.configured_example_endpoint(), public + '/demo/endpoint')
            # A prior local config cannot authorize an HTTP preview request.
            self.assertEqual(self.client.get('/demo-config').json(), {})
        with patch.dict(os.environ, ARISEC_PUBLIC_ORIGIN='', ARISEC_LOCAL_PREVIEW='0'):
            self.assertIsNone(e.configured_example_endpoint())

    def test_public_duplicate_authorities_and_wrong_scope_are_denied(self):
        public = 'https://demo.example.com'
        headers = [(b'host', b'demo.example.com'), (b'origin', public.encode())]
        scope = {'type': 'http', 'scheme': 'https', 'method': 'POST', 'path': '/scan', 'headers': headers}
        with patch.dict(os.environ, ARISEC_PUBLIC_ORIGIN=public, ARISEC_LOCAL_PREVIEW='0'):
            request = Request(scope)
            for extra in [(b'host', b'demo.example.com'), (b'origin', public.encode())]:
                scope['headers'] = headers + [extra]
                self.assertFalse(e.example_request_allowed(request, public + '/demo/endpoint'))
            scope['headers'] = headers
            scope['path'] = '/other'
            self.assertFalse(e.example_request_allowed(request, public + '/demo/endpoint'))
            scope['path'] = '/scan'
            scope['scheme'] = 'http'
            self.assertFalse(e.example_request_allowed(request, public + '/demo/endpoint'))


if __name__ == '__main__':
    unittest.main()
