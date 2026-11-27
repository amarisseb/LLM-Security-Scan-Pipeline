"""Self-serve integration, with no lifespan, engine jobs or external network."""
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import accounts, attestation, main, scan_store


class CustomerJourneyTests(unittest.TestCase):
    origin = "https://journey.example"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.log = self.root / "attestations.jsonl"
        self.store = scan_store.ScanStore(self.root / "runs")
        self.executor = main.BoundedScanExecutor(max_pending=2)
        self.addCleanup(self.executor.shutdown)
        patches = [
            patch.dict(os.environ, {
                "ARISEC_SELF_SERVE": "1", "ARISEC_LOCAL_DEMO": "0",
                "ARISEC_LOCAL_PREVIEW": "0",
                "ARISEC_ACCOUNTS_DB": str(self.root / "accounts.sqlite3"),
                "ATTESTATION_LOG_PATH": str(self.log),
            }),
            patch.object(main, "store", self.store),
            patch.object(main, "_scan_executor", self.executor),
            patch.object(main.rate_limiter, "check_and_record", return_value=SimpleNamespace(allowed=True)),
            patch("app.provider_generator.validate_target"),
            patch.object(main.url_safety, "validate_target_url"),
            patch.object(main, "_enqueue_api_scan", side_effect=self.fake_enqueue),
        ]
        mocks = [p.start() for p in patches]
        self.addCleanup(lambda: [p.stop() for p in reversed(patches)])
        self.validate_provider, self.dns, self.enqueue = mocks[4:]
        # No context manager: application startup/recovery and purge never run.
        self.client = self.new_client()

    def new_client(self, *, raise_server_exceptions=True):
        client = TestClient(main.app, base_url=self.origin, client=("198.51.100.20", 41000),
                            raise_server_exceptions=raise_server_exceptions)
        client.headers.update({"Origin": self.origin})
        self.addCleanup(client.close)
        return client

    def fake_enqueue(self, scan_id, provider, model, api_key, *, lease):
        # Consume admission exactly as a completed fake dispatch would, without
        # running an engine or leaving reserved leases behind between requests.
        self.executor.release(lease)

    def guest(self, client=None):
        client = client or self.client
        response = client.get("/account/session")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["guest"])
        token = client.cookies.get(accounts.COOKIE_NAME)
        self.assertIsNotNone(token)
        return accounts.session_principal(token)

    def body(self):
        return dict(mode="api", api_provider="openai", api_model="gpt-4o-mini",
                    api_key="fake-key-never-sent", agreed_to_attestation=True,
                    attestation_version=attestation.CURRENT_ATTESTATION_VERSION)

    def post_scan(self):
        return self.client.post("/scan", json=self.body())

    def test_guest_once_and_new_cookie_cannot_reset_network_credit(self):
        self.guest()
        first = self.post_scan()
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(self.post_scan().status_code, 402)
        other = self.new_client()
        self.guest(other)
        self.assertEqual(other.post("/scan", json=self.body()).status_code, 402)
        self.assertEqual(self.enqueue.call_count, 1)
        self.dns.assert_not_called()

    def test_failed_job_refunds_guest_credit(self):
        principal = self.guest()
        first = self.post_scan()
        self.assertEqual(first.status_code, 202, first.text)
        self.assertFalse(accounts.free_scan_available(principal, "198.51.100.20"))
        main._finish(first.json()["scan_id"], status=scan_store.FAILED, error_code="scan_failed")
        self.assertTrue(accounts.free_scan_available(principal, "198.51.100.20"))
        self.assertEqual(self.post_scan().status_code, 202)

    def test_queue_failure_refunds_credit_and_releases_admission(self):
        principal = self.guest()
        with patch.object(main, "_enqueue_api_scan", side_effect=RuntimeError("fake queue failure")):
            response = self.post_scan()
        self.assertEqual(response.status_code, 503, response.text)
        self.assertTrue(accounts.free_scan_available(principal, "198.51.100.20"))
        leases = [self.executor.reserve(), self.executor.reserve()]
        self.assertTrue(all(leases))
        for lease in leases:
            self.executor.release(lease)
        self.assertEqual(self.post_scan().status_code, 202)

    def test_attestation_failure_refunds_credit(self):
        principal = self.guest()
        with patch.object(attestation, "log_attestation", side_effect=OSError("fake disk failure")):
            response = self.post_scan()
        self.assertEqual(response.status_code, 500, response.text)
        self.assertTrue(accounts.free_scan_available(principal, "198.51.100.20"))
        self.enqueue.assert_not_called()
        self.assertEqual(self.post_scan().status_code, 202)

    def test_refund_database_error_still_releases_queue_lease(self):
        self.guest()
        client = self.new_client(raise_server_exceptions=False)
        client.cookies.update(self.client.cookies)
        with patch.object(main, "_enqueue_api_scan", side_effect=RuntimeError("fake queue failure")), \
                patch.object(accounts, "refund_free_scan", side_effect=sqlite3.OperationalError("fake database lock")):
            response = client.post("/scan", json=self.body())
        self.assertIn(response.status_code, (500, 503))
        leases = [self.executor.reserve(), self.executor.reserve()]
        try:
            self.assertTrue(all(leases), "Refund errors must not leak a queue reservation")
        finally:
            for lease in leases:
                if lease is not None:
                    self.executor.release(lease)

    def test_restart_interrupted_job_restores_guest_credit(self):
        principal = self.guest()
        response = self.post_scan()
        self.assertEqual(response.status_code, 202, response.text)
        sid = response.json()["scan_id"]
        main._housekeeping(recover_interrupted=True)
        self.assertEqual(self.store.get(sid)["status"], scan_store.FAILED)
        self.assertEqual(self.store.get(sid)["error_code"], "interrupted")
        self.assertTrue(accounts.free_scan_available(principal, "198.51.100.20"),
                        "Restart recovery must refund failed guest jobs")
        self.assertEqual(self.post_scan().status_code, 202)

    def test_signup_preserves_report_owner_rotates_cookie_and_freezes_attestation(self):
        principal = self.guest()
        old_token = self.client.cookies.get(accounts.COOKIE_NAME)
        response = self.post_scan()
        self.assertEqual(response.status_code, 202, response.text)
        sid = response.json()["scan_id"]
        report = self.store.scan_dir(sid) / "fixture.report.jsonl"
        report.write_text("{}\n", encoding="utf-8")
        main._finish(sid, status=scan_store.COMPLETE, report_file=report.name)
        frozen = self.log.read_bytes()
        record = json.loads(frozen)
        self.assertIsNone(record["user_email"])
        self.assertEqual(record["principal_id"], principal["id"])
        self.assertEqual(record["attestation_sha256"], hashlib.sha256(
            attestation.ATTESTATION_TEXTS[record["attestation_version"]].encode()).hexdigest())
        signup = self.client.post("/account/signup", json={
            "email": "customer@example.com", "password": "strong-test-password-42"})
        self.assertEqual(signup.status_code, 201, signup.text)
        promoted = accounts.session_principal(self.client.cookies.get(accounts.COOKIE_NAME))
        self.assertEqual(promoted["id"], principal["id"])
        self.assertIsNone(accounts.session_principal(old_token))
        self.assertEqual(self.log.read_bytes(), frozen)
        self.assertEqual(self.store.get(sid)["owner_id"], principal["id"])
        self.assertEqual(self.post_scan().status_code, 402)
        with patch.object(main.results, "build_report", return_value={"scan_id": sid}) as build:
            self.assertEqual(self.client.get(f"/scan/{sid}").status_code, 200)
            self.assertEqual(self.client.get(f"/scan/{sid}/report").status_code, 200)
            build.assert_called_once()
            build.reset_mock()
            other = self.new_client()
            self.guest(other)
            self.assertEqual(other.get(f"/scan/{sid}").status_code, 404)
            self.assertEqual(other.get(f"/scan/{sid}/report").status_code, 404)
            build.assert_not_called()

    def test_unverified_endpoint_rejected_before_dns_or_credit(self):
        principal = self.guest()
        response = self.client.post("/scan", json=dict(
            mode="http", target_url="https://unverified.example/chat",
            http_request_template={"message": "{{prompt}}"}, http_response_path="answer",
            agreed_to_attestation=True, attestation_version=attestation.CURRENT_ATTESTATION_VERSION))
        self.assertEqual(response.status_code, 403, response.text)
        self.dns.assert_not_called()
        self.enqueue.assert_not_called()
        self.assertTrue(accounts.free_scan_available(principal, "198.51.100.20"))

    def test_cookie_mutation_requires_same_origin(self):
        self.guest()
        response = self.client.post("/scan", json=self.body(), headers={"Origin": "https://attacker.example"})
        self.assertEqual(response.status_code, 403)
        self.enqueue.assert_not_called()
        self.validate_provider.assert_not_called()


if __name__ == "__main__":
    unittest.main()
