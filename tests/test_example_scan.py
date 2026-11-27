"""Local example admission uses the real boundary, isolated state and no jobs."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import main, accounts, attestation, lab_policy, scan_store


class ExampleScanTests(unittest.TestCase):
    target = 'http://127.0.0.1:63820/demo/endpoint'

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.store = scan_store.ScanStore(root / 'runs')
        self.executor = main.BoundedScanExecutor(max_pending=2)
        self.addCleanup(self.executor.shutdown)
        patches = [patch.dict(os.environ, {
            'ARISEC_SELF_SERVE':'1','ARISEC_LOCAL_PREVIEW':'1','ARISEC_LOCAL_DEMO':'0',
            'ARISEC_EXAMPLE_ENDPOINT':self.target,'ARISEC_ACCOUNTS_DB':str(root/'accounts.db'),
            'ATTESTATION_LOG_PATH':str(root/'attestations.jsonl')}),
            patch.object(main,'store',self.store),patch.object(main,'_scan_executor',self.executor),
            patch.object(lab_policy,'_targets',(self.target,)),
            patch.object(main,'_enqueue_application_scan',side_effect=lambda *args,lease,**kw:self.executor.release(lease)),
            patch.object(main.url_safety,'validate_target_url')]
        mocks=[p.start() for p in patches]
        self.addCleanup(lambda:[p.stop() for p in reversed(patches)])
        self.enqueue,self.dns=mocks[-2:]
        self.client=self.client_for()
        self.assertEqual(self.client.get('/account/session').status_code,200)

    def client_for(self,peer='127.0.0.1'):
        client=TestClient(main.app,base_url='http://127.0.0.1:63820',client=(peer,1234))
        client.headers['Origin']='http://127.0.0.1:63820'
        self.addCleanup(client.close)
        return client

    def body(self,target=None):
        return dict(mode='http',target_url=target or self.target,
                    http_request_template={'message':'{{prompt}}'},http_response_path='answer',
                    agreed_to_attestation=True,attestation_version=attestation.CURRENT_ATTESTATION_VERSION)

    def test_exact_example_queues_and_preserves_free_credit(self):
        response=self.client.post('/scan',json=self.body())
        self.assertEqual(response.status_code,202,response.text)
        self.assertTrue(self.store.get(response.json()['scan_id'])['is_demo'])
        self.assertTrue(self.client.get('/account/session').json()['free_scan_available'])
        self.dns.assert_not_called()
        self.enqueue.assert_called_once()

    def test_example_has_separate_limits_from_real_assessments(self):
        principal=accounts.session_principal(self.client.cookies.get(accounts.COOKIE_NAME))
        self.assertTrue(accounts.reserve_free_scan(principal,'127.0.0.1','used-real-trial'))
        with patch.object(main.rate_limiter,'check_and_record',side_effect=AssertionError('real scan allowance must not be consumed')):
            for _ in range(4):
                response=self.client.post('/scan',json=self.body())
                self.assertEqual(response.status_code,202,response.text)
        self.assertFalse(self.client.get('/account/session').json()['free_scan_available'])

    def test_exception_does_not_cover_other_local_addresses_or_paths(self):
        for target in [self.target+'/other',self.target.replace('63820','63821'),
                       'http://169.254.169.254/latest/meta-data/','http://127.0.0.1:63820/admin']:
            with self.subTest(target=target):
                self.assertEqual(self.client.post('/scan',json=self.body(target)).status_code,403)
        self.enqueue.assert_not_called()
        self.dns.assert_not_called()

    def test_remote_and_cross_origin_cannot_use_the_exception(self):
        remote=self.client_for('198.51.100.30')
        remote.cookies.update(self.client.cookies)
        self.assertEqual(remote.post('/scan',json=self.body()).status_code,403)
        self.assertEqual(self.client.post('/scan',json=self.body(),headers={'Origin':'https://attacker.example'}).status_code,403)
        self.enqueue.assert_not_called()

    def test_worker_gets_only_exact_example_and_report_is_labelled_demo(self):
        sid=self.client.post('/scan',json=self.body()).json()['scan_id']
        captured=[]
        report=self.store.scan_dir(sid)/'fixture.report.jsonl'
        report.write_text('{}\n')
        def run(kind,scan_id,payload,*args,**kwargs):
            captured.append(copy.deepcopy(payload))
            return report
        with patch.object(main,'run_isolated_job',side_effect=run),patch.object(main.results,'answered_any',return_value=True):
            main._run_isolated_scan('http',sid,{'url':self.target})
        self.assertTrue(captured[0]['scripted_demo'])
        self.assertNotIn('lab_targets',captured[0])
        self.assertEqual(captured[0]['prompt_cap'],1)
        with patch.object(main.results,'build_report',return_value={'categories':[]}):
            result=self.client.get('/scan/'+sid+'/report')
            self.assertEqual(result.status_code,200,result.text)
            self.assertTrue(result.json()['simulation'])


if __name__=='__main__':
    unittest.main()
