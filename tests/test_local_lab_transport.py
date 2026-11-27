import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from app import application_generator as connector, lab_policy, url_safety


class LocalLabTransportTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                requests.append((self.path, payload, self.headers.get('Authorization')))
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', 'http://169.254.169.254/latest/meta-data')
                    self.end_headers()
                    return
                result = json.dumps({'textResponse': payload['message']}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(result)))
                self.end_headers()
                self.wfile.write(result)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f'http://127.0.0.1:{self.server.server_address[1]}/chat'
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(lambda: lab_policy.configure_local_targets([]))
        lab_policy.configure_local_targets([self.endpoint])

    def test_real_http_post_is_limited_to_registered_endpoint(self):
        connector.validate_connection(self.endpoint, {'message': '{{prompt}}'}, 'textResponse')
        with patch.object(connector, '_resolve_public', side_effect=AssertionError('DNS must not run')):
            result = connector.post_json(self.endpoint, {'message': 'hello'}, 'local-secret')
        self.assertEqual(result['textResponse'], 'hello')
        self.assertEqual(self.requests, [('/chat', {'message': 'hello'}, 'Bearer local-secret')])

    def test_neighbouring_path_and_default_policy_still_blocked(self):
        for endpoint in [self.endpoint + '/admin', self.endpoint.replace('/chat', '/admin')]:
            with self.assertRaises(connector.ApplicationConfigError):
                connector.validate_connection(endpoint, {'message': '{{prompt}}'}, 'textResponse')
        lab_policy.configure_local_targets([])
        with self.assertRaises(connector.ApplicationRequestError):
            connector.post_json(self.endpoint, {'message': 'hello'})
        self.assertEqual(self.requests, [])

    def test_redirect_to_metadata_is_never_followed(self):
        endpoint = self.endpoint.replace('/chat', '/redirect')
        lab_policy.configure_local_targets([endpoint])
        with self.assertRaises(connector.ApplicationRequestError):
            connector.post_json(endpoint, {'message': 'hello'})
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0][0], '/redirect')

    def test_production_url_validation_is_unchanged(self):
        self.assertFalse(url_safety.validate_target_url(self.endpoint).is_safe)
        self.assertTrue(lab_policy.is_local_target(self.endpoint))


if __name__ == '__main__':
    unittest.main()
