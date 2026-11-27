from contextlib import closing
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import accounts, assessment_api
from app.security import SecurityBoundaryMiddleware


class AssessmentApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {"ARISEC_SELF_SERVE": "1", "ARISEC_LOCAL_PREVIEW": "1",
                                     "ARISEC_LOCAL_ASSURANCE": "1", "ARISEC_LOCAL_DEMO": "0",
                                     "ARISEC_ACCOUNTS_DB": str(Path(self.temp.name) / "accounts.sqlite3")})
        env.start()
        self.addCleanup(env.stop)
        self.owner, self.token = accounts.create_guest_session()
        _, self.other_token = accounts.create_guest_session()

    def client(self, token=None, remote=False):
        app = FastAPI()
        assessment_api.register_assessment_routes(app)
        client = TestClient(SecurityBoundaryMiddleware(app), base_url="https://example.com" if remote else "http://127.0.0.1:8000",
                            client=("203.0.113.1" if remote else "127.0.0.1", 12345))
        self.addCleanup(client.close)
        if token:
            client.cookies.set(accounts.COOKIE_NAME, token)
        return client

    def start(self, client, body=None):
        return client.post("/account/assurance/runs", json=body if body is not None else {"agreed_to_local_test": True},
                           headers={"Origin": "http://127.0.0.1:8000"})

    def test_public_recorded_result_is_explicit_and_does_not_expose_paths(self):
        with patch.object(assessment_api, "prepared", return_value=True):
            result = self.client(remote=True).get("/assessments").json()
        self.assertFalse(result["local_enabled"])
        self.assertFalse(result["local_ready"])
        self.assertEqual(result["reference"]["source"], "recorded_local_benchmark")
        self.assertEqual(result["reference"]["assessment"]["outcome"], "benchmark_goal_not_observed")
        self.assertNotIn(str(assessment_api.ROOT), json.dumps(result))
        self.assertEqual(result["capabilities"]["adaptive_campaigns"], "in_development")

    def test_deployment_flag_and_remote_requests_cannot_launch(self):
        with patch.object(assessment_api, "_submit") as submit:
            response = self.client(self.token, remote=True).post("/account/assurance/runs", json={"agreed_to_local_test": True}, headers={"Origin": "https://example.com"})
            self.assertEqual(response.status_code, 403)
            with patch.dict(os.environ, {"ARISEC_LOCAL_ASSURANCE": "0"}):
                self.assertEqual(self.start(self.client(self.token)).status_code, 403)
            submit.assert_not_called()

    def test_missing_session_and_cross_origin_denied(self):
        self.assertIn(self.start(self.client()).status_code, (401, 403))
        response = self.client(self.token).post("/account/assurance/runs", json={"agreed_to_local_test": True}, headers={"Origin": "https://attacker.example"})
        self.assertEqual(response.status_code, 403)

    def test_consent_explicit_and_no_user_engine_arguments(self):
        with patch.object(assessment_api, "prepared", return_value=True), patch.object(assessment_api, "_submit") as submit:
            for body in ({}, {"agreed_to_local_test": 1}, {"agreed_to_local_test": False},
                         {"agreed_to_local_test": True, "endpoint": "http://169.254.169.254"}, []):
                with self.subTest(body=body):
                    self.assertEqual(self.start(self.client(self.token), body).status_code, 422)
            submit.assert_not_called()

    def test_one_running_job_and_owner_private_results(self):
        first = self.client(self.token)
        other = self.client(self.other_token)
        with patch.object(assessment_api, "prepared", return_value=True), patch.object(assessment_api, "_submit") as submit:
            response = self.start(first)
            self.assertEqual(response.status_code, 202, response.text)
            run_id = response.json()["run_id"]
            self.assertEqual(submit.call_args.args[0], run_id)
            lease = submit.call_args.args[1]
            self.addCleanup(lease.close)
            self.assertEqual(self.start(other).status_code, 409)
        self.assertEqual(first.get("/account/assurance/runs/latest").json()["run_id"], run_id)
        self.assertIsNone(other.get("/account/assurance/runs/latest").json()["run_id"])
        self.assertEqual(other.get("/account/assurance/runs/" + run_id).status_code, 404)
        assessment_api._finish(run_id, "complete", assessment_api.REFERENCE)
        self.assertEqual(first.get("/account/assurance/runs/" + run_id).json()["result"]["assessment"]["outcome"], "benchmark_goal_not_observed")
        with closing(accounts.connect_db()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM guest_reservations").fetchone()[0], 0)

    def test_launch_failure_is_recorded_without_internal_error(self):
        client = self.client(self.token)
        with patch.object(assessment_api, "prepared", return_value=True), patch.object(assessment_api, "_submit", side_effect=OSError("secret internal path")):
            response = self.start(client)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("secret", response.text)
        self.assertEqual(client.get("/account/assurance/runs/latest").json()["status"], "failed")

    def test_interrupted_run_recovers_only_after_process_lease_released(self):
        client = self.client(self.token)
        with patch.object(assessment_api, "prepared", return_value=True), patch.object(assessment_api, "_submit") as submit:
            run_id = self.start(client).json()["run_id"]
            lease = submit.call_args.args[1]
            self.addCleanup(lease.close)
            self.assertEqual(client.get("/account/assurance/runs/" + run_id).json()["status"], "running")
            lease.close()
            self.assertEqual(client.get("/account/assurance/runs/" + run_id).json()["status"], "interrupted")

    def test_normalisation_rechecks_grading_and_strips_raw_data(self):
        raw = {"schema": "arisec.agentdojo.v1", "phases": {
            "clean_user": {"status": "complete", "utility": False},
            "goal_capability": {"status": "complete", "utility": True},
            "attacked": {"status": "complete", "utility": True, "security": False}},
            "assessment": {"outcome": "secure"}, "model": "secret", "api_key": "secret", "messages": ["secret"]}
        result = assessment_api._safe_summary(raw)
        self.assertEqual(result["assessment"]["outcome"], "inconclusive")
        self.assertNotIn("secret", json.dumps(result))
        raw["phases"]["clean_user"] = {"status": "inconclusive", "utility": True}
        result = assessment_api._safe_summary(raw)
        self.assertIsNone(result["phases"]["clean_user"]["utility"])
        self.assertEqual(result["assessment"]["outcome"], "inconclusive")
