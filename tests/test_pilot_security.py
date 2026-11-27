import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import main, scan_store, attestation


class PilotSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        config = Path(self.tmp.name) / 'accounts.json'
        self.tokens = {'alice': 'a' * 48, 'bob': 'b' * 48}
        config.write_text(json.dumps([dict(id=k, email=k+'@example.com',
            token_sha256=hashlib.sha256(v.encode()).hexdigest(), allowed_origins=['https://example.com'])
            for k,v in self.tokens.items()]))
        self.store = scan_store.ScanStore(Path(self.tmp.name) / 'runs')
        self.executor = main.BoundedScanExecutor(max_pending=1)
        self.addCleanup(self.executor.shutdown)
        patches = [patch.dict(os.environ, {'ARISEC_ACCOUNTS_FILE': str(config), 'ARISEC_LOCAL_DEMO': '0'}),
                   patch.object(main, 'store', self.store), patch.object(main, '_scan_executor', self.executor),
                   patch.object(main.url_safety, 'validate_target_url'), patch.object(main, '_enqueue_application_scan'),
                   patch.object(main.attestation, 'log_attestation')]
        self.mocks = [p.start() for p in patches]
        self.addCleanup(lambda: [p.stop() for p in reversed(patches)])
        self.client = TestClient(main.app, base_url='https://testserver')

    def headers(self, who='alice'):
        return {'Authorization': 'Bearer '+self.tokens[who]}

    def body(self, **extra):
        return dict(mode='http', target_url='https://example.com/ai',
                    http_request_template={'message': '{{prompt}}'}, http_response_path='answer',
                    user_email='forged@example.com', agreed_to_attestation=True,
                    attestation_version=attestation.CURRENT_ATTESTATION_VERSION, **extra)

    def test_report_link_is_not_authority_and_legacy_records_are_private(self):
        sid = '1' * 32
        self.store.create(sid, 'https://example.com', owner_id='alice')
        self.store.create('2'*32, 'https://example.com')
        self.assertEqual(self.client.get('/scan/'+sid, headers=self.headers()).status_code, 200)
        for route in ['/scan/'+sid, '/scan/'+sid+'/report', '/scan/'+'2'*32]:
            self.assertEqual(self.client.get(route, headers=self.headers('bob')).status_code, 404)
        self.assertEqual(self.client.get('/scan/'+sid).status_code, 401)

    def test_denied_target_and_browser_do_not_reach_dns(self):
        body = self.body(); body['target_url'] = 'https://unapproved.example/ai'
        self.assertEqual(self.client.post('/scan', headers=self.headers(), json=body).status_code, 403)
        web = dict(mode='web', target_url='https://example.com', user_email='alice@example.com',
                   attestation_version=attestation.CURRENT_ATTESTATION_VERSION, agreed_to_attestation=True)
        self.assertEqual(self.client.post('/scan', headers=self.headers(), json=web).status_code, 403)
        self.mocks[3].assert_not_called()
        self.assertFalse(self.client.get('/security-config').json()['web_scanning_available'])

    def test_account_email_is_used_without_a_form_email_field(self):
        self.mocks[3].return_value.is_safe = True
        body = self.body()
        body.pop('user_email')
        response = self.client.post('/scan', headers=self.headers(), json=body)
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(self.mocks[5].call_args.kwargs['user_email'], 'alice@example.com')

    def test_selected_sector_is_stored_and_forwarded_only_for_application_scans(self):
        self.mocks[3].return_value.is_safe = True
        body = self.body(scenario_sector='legal')
        response = self.client.post('/scan', headers=self.headers(), json=body)
        self.assertEqual(response.status_code,202,response.text)
        self.assertEqual(self.store.get(response.json()['scan_id'])['scenario_sector'],'legal')
        self.assertEqual(self.mocks[4].call_args.kwargs['scenario_sector'],'legal')

    def test_admission_is_bounded_before_dns_and_logs_authenticated_actor(self):
        self.mocks[3].return_value.is_safe = True
        response = self.client.post('/scan', headers=self.headers(), json=self.body())
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(self.store.get(response.json()['scan_id'])['owner_id'], 'alice')
        self.assertEqual(self.mocks[5].call_args.kwargs['user_email'], 'alice@example.com')
        self.mocks[3].reset_mock()
        response = self.client.post('/scan', headers=self.headers(), json=self.body())
        self.assertEqual(response.status_code, 503)
        self.mocks[3].assert_not_called()

    def test_oversized_body_and_http_are_rejected_before_dns(self):
        response = self.client.post('/scan', headers=self.headers(), content=b'x'*131073)
        self.assertEqual(response.status_code, 413)
        insecure = TestClient(main.app, base_url='http://testserver')
        self.assertEqual(insecure.post('/scan', headers=self.headers(), json=self.body()).status_code, 403)
        self.mocks[3].assert_not_called()
