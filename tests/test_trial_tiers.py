"""The trial-to-consultation boundary, through actual account and scan routes."""
import time
import unittest
from app import billing
import test_customer_journey as fixtures


class TrialTierTests(unittest.TestCase):
    origin=fixtures.CustomerJourneyTests.origin
    setUp=fixtures.CustomerJourneyTests.setUp
    new_client=fixtures.CustomerJourneyTests.new_client
    fake_enqueue=fixtures.CustomerJourneyTests.fake_enqueue
    guest=fixtures.CustomerJourneyTests.guest
    body=fixtures.CustomerJourneyTests.body
    post_scan=fixtures.CustomerJourneyTests.post_scan

    def register(self):
        response=self.client.post('/account/signup',json={'email':'trial@example.com','password':'a-strong-test-password-123'})
        self.assertEqual(response.status_code,201,response.text)

    def test_free_profile_is_stored_and_full_cannot_be_requested_by_guest(self):
        self.guest()
        body=self.body();body['scan_profile']='full'
        response=self.client.post('/scan',json=body)
        self.assertEqual(response.status_code,402,response.text)
        self.validate_provider.assert_not_called()
        self.enqueue.assert_not_called()
        response=self.post_scan()
        self.assertEqual(response.status_code,202,response.text)
        self.assertEqual(self.store.get(response.json()['scan_id'])['scan_profile'],'free')

    def test_signup_and_consultation_do_not_reset_trial_or_unlock_full(self):
        self.guest()
        self.assertEqual(self.post_scan().status_code,202)
        self.register()
        self.assertFalse(self.client.get('/account/session').json()['free_scan_available'])
        self.assertEqual(self.post_scan().status_code,402)
        request=self.client.post('/account/consultation',json={'message':'Please discuss a broader assessment.'})
        self.assertEqual(request.status_code,201,request.text)
        self.assertEqual(self.client.get('/account/consultation').json()['request_id'],request.json()['request_id'])
        self.assertFalse(self.client.get('/account/plan').json()['full_scan_access'])
        body=self.body();body['scan_profile']='full'
        self.assertEqual(self.client.post('/scan',json=body).status_code,402)

    def test_only_operator_grant_unlocks_full_and_expiry_revokes_it(self):
        principal=self.guest()
        self.register()
        body=self.body();body['scan_profile']='full'
        self.assertEqual(self.client.post('/scan',json=body).status_code,402)
        billing.grant_subscription(principal['id'],'full',time.time()+3600)
        response=self.client.post('/scan',json=body)
        self.assertEqual(response.status_code,202,response.text)
        self.assertEqual(self.store.get(response.json()['scan_id'])['scan_profile'],'full')
        self.assertTrue(self.client.get('/account/plan').json()['full_scan_access'])
        billing.grant_subscription(principal['id'],'full',time.time()-1)
        self.assertEqual(self.client.post('/scan',json=body).status_code,402)


if __name__=='__main__':
    unittest.main()
