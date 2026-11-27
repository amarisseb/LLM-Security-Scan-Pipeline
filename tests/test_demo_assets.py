import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.demo_assets import register_demo_assets


class DemoAssetTests(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        register_demo_assets(app)
        self.client = TestClient(app)

    def test_public_library_is_fictional_and_has_twelve_unique_cases(self):
        response = self.client.get('/demo/scenarios.json')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual({s['id'] for s in data['sectors']}, {'legal','healthcare','education'})
        cases = [c for s in data['sectors'] for c in s['cases']]
        self.assertEqual(len(cases), 12)
        self.assertEqual(len({c['id'] for c in cases}),12)
        for c in cases:
            self.assertIn('fictional',c['prompt'].lower())
            self.assertEqual(c['weak_response'],c['marker'])
            self.assertNotEqual(c['strong_response'],c['marker'])
            self.assertIn('not domain accuracy or compliance',c['scope_note'])

    def test_query_parameters_cannot_choose_a_file(self):
        response = self.client.get('/demo/scenarios.json?filename=../app/security.py')
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['version'],1)
        self.assertEqual(self.client.get('/demo/accounts.json').status_code,404)

    def test_demo_assets_do_not_offer_a_scan_action(self):
        self.assertEqual(self.client.post('/demo/scenarios.json',json={'url':'http://127.0.0.1'}).status_code,405)
