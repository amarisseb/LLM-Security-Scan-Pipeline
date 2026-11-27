"""Remediation previews are public; full educational guides need registration."""
import unittest
from unittest.mock import patch
from app import main,scan_store
import test_customer_journey as fixtures


class GuidanceAccessTests(unittest.TestCase):
    origin=fixtures.CustomerJourneyTests.origin
    setUp=fixtures.CustomerJourneyTests.setUp
    new_client=fixtures.CustomerJourneyTests.new_client
    fake_enqueue=fixtures.CustomerJourneyTests.fake_enqueue
    guest=fixtures.CustomerJourneyTests.guest

    def register(self):
        r=self.client.post('/account/signup',json={'email':'guides@example.com','password':'a-secure-test-password-123'})
        self.assertEqual(r.status_code,201,r.text)

    def test_public_catalog_has_only_short_prompt_injection_preview(self):
        response=self.client.get('/security-guidance')
        self.assertEqual(response.status_code,200)
        self.assertEqual(set(response.json()['categories']),{'promptinject'})
        steps = response.json()['categories']['promptinject']['flagged']['steps']
        self.assertEqual(len(steps), 1)
        self.assertIn('pass the customer message separately', steps[0]['action'])
        checks = steps[0]['verification_examples']
        self.assertEqual(len(checks), 2)
        self.assertIn('ordinary', checks[0]['input'])
        self.assertIn('flagged', checks[1]['input'])

    def test_guest_cannot_read_full_guide_but_signup_unlocks_examples_not_paid_scans(self):
        self.guest()
        self.assertEqual(self.client.get('/account/guidance/dan').status_code,403)
        other=self.new_client()
        self.assertEqual(other.get('/account/guidance/dan').status_code,401)
        self.register()
        response=self.client.get('/account/guidance/dan')
        self.assertEqual(response.status_code,200,response.text)
        self.assertTrue(response.json()['example_guidance'])
        self.assertEqual(response.json()['plan']['status'],'not_tested')
        self.assertEqual(len(response.json()['plan']['steps']),3)
        self.assertFalse(self.client.get('/account/plan').json()['full_scan_access'])

    def test_guest_demo_report_redacts_other_category_plans_server_side(self):
        principal=self.guest()
        sid='d'*32
        self.store.create(sid,'Built-in demo',owner_id=principal['id'])
        path=self.store.scan_dir(sid)/'fixture.report.jsonl'
        path.write_text('{}\n')
        self.store.update(sid,is_demo=True,scan_profile='full',status=scan_store.COMPLETE,report_file=path.name)
        def report(*args,**kwargs):
            return {'categories':[{'key':key,'action_plan':{'private_marker':'full educational plan'},'recommendation':'full educational recommendation'} for key in ('promptinject','dan','encoding','sysprompt_extraction','donotanswer')]}
        with patch.object(main.results,'build_report',side_effect=report):
            response=self.client.get('/scan/'+sid+'/report')
            self.assertEqual(response.status_code,200,response.text)
            self.assertTrue(response.json()['preview_mode'])
            for category in response.json()['categories'][1:]:
                self.assertNotIn('action_plan',category)
                self.assertTrue(category['remediation_locked'])
            self.register()
            signed_in=self.client.get('/scan/'+sid+'/report').json()
            self.assertIn('action_plan',signed_in['categories'][1])


if __name__=='__main__':
    unittest.main()
