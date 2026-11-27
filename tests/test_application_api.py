import json
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main, scan_store, attestation
from app.rate_limit import ScanRateLimiter


class ApplicationAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = scan_store.ScanStore(Path(self.tmp.name) / "runs")
        account_path = Path(self.tmp.name) / "accounts.json"
        self.invite = "test-invite-token-" + "a" * 32
        account_path.write_text(json.dumps([dict(id="owner", email="owner@example.com",
            token_sha256=hashlib.sha256(self.invite.encode()).hexdigest(), allowed_origins=["https://example.com"])]))
        self.env = patch.dict(os.environ, {"ARISEC_ACCOUNTS_FILE": str(account_path), "ARISEC_LOCAL_DEMO": "0"})
        self.env.start()
        self.addCleanup(self.env.stop)
        executor = main.BoundedScanExecutor(max_pending=100)
        self.addCleanup(executor.shutdown)
        self.patches = [
            patch.object(main, "store", self.store),
            patch.object(main, "rate_limiter", ScanRateLimiter(max_per_hour=100)),
            patch.object(main.url_safety, "validate_target_url"),
            patch.object(main.attestation, "log_attestation"),
            patch.object(main, "_enqueue_application_scan"),
            patch.object(main, "_scan_executor", executor),
        ]
        self.started = [p.start() for p in self.patches]
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patches)])
        self.started[2].return_value.is_safe = True
        self.client = TestClient(main.app, base_url="https://testserver", headers={"Authorization": "Bearer " + self.invite})

    def body(self, **kwargs):
        return {
            "mode": "http", "target_url": "https://example.com/summarize",
            "http_request_template": {"document": "{{prompt}}", "mode": "summarize"},
            "http_response_path": "result.text", "api_key": "token-NEVER-PERSIST",
            "component_name": "Document summary", "component_type": "summarizer",
            "user_email": "owner@example.com", "agreed_to_attestation": True,
            "attestation_version": attestation.CURRENT_ATTESTATION_VERSION, **kwargs,
        }

    def test_metadata_stored_separately_from_secret_connection(self):
        response = self.client.post("/scan", json=self.body())
        self.assertEqual(response.status_code, 202, response.text)
        sid = response.json()["scan_id"]
        self.assertEqual(self.store.get(sid)["component_name"], "Document summary")
        status = self.client.get(f"/scan/{sid}").json()
        self.assertEqual(status["component_type"], "summarizer")
        self.assertEqual(status["mode"], "http")
        disk = (self.store.scan_dir(sid) / "status.json").read_text()
        self.assertNotIn("token-NEVER-PERSIST", disk)
        self.assertNotIn("http_request_template", disk)
        queued = self.started[4].call_args.args
        self.assertEqual(queued[2], self.body()["http_request_template"])
        self.assertEqual(queued[4], "token-NEVER-PERSIST")
        self.assertNotIn("token-NEVER-PERSIST", repr(self.started[3].call_args))

    def test_public_address_gate_applies_to_application_api(self):
        self.started[2].return_value.is_safe = False
        response = self.client.post("/scan", json=self.body(target_url="https://127.0.0.1/ai"))
        self.assertEqual(response.status_code, 403)
        self.started[4].assert_not_called()

    def test_validation_precedes_queueing(self):
        invalid = [
            {"target_url": "http://example.com"},
            {"http_request_template": {"q": "not a marker"}},
            {"http_response_path": "x[0]"},
            {"api_provider": "openai"},
        ]
        for values in invalid:
            with self.subTest(values=values):
                expected = 403 if values.get("target_url", "").startswith("http:") else 400
                self.assertEqual(self.client.post("/scan", json=self.body(**values)).status_code, expected)
        self.started[4].assert_not_called()

    def test_explicit_consent_is_required(self):
        self.assertEqual(self.client.post("/scan", json=self.body(agreed_to_attestation="true")).status_code, 400)
        self.started[4].assert_not_called()

    def test_worker_auth_failure_has_no_credential_in_response(self):
        from app.application_generator import ApplicationAuthError
        sid = "a" * 32
        self.store.create(sid, "https://example.com/ai", mode="http", owner_id="owner")
        with patch.object(main.application_scan, "run_application_scan", side_effect=ApplicationAuthError("token-NEVER-PERSIST")):
            main._run_application_scan_job(sid, "https://example.com/ai", {"q": "{{prompt}}"}, "answer", "token-NEVER-PERSIST")
        response = self.client.get(f"/scan/{sid}")
        self.assertEqual(response.json()["error"]["code"], "application_auth_failed")
        self.assertNotIn("token-NEVER-PERSIST", response.text)

    def test_report_includes_component_identity(self):
        sid = "b" * 32
        self.store.create(sid, "https://example.com/ai", mode="http", component_name="Search", component_type="search", owner_id="owner")
        report = self.store.scan_dir(sid) / "garak.unit.report.jsonl"
        report.write_text(json.dumps({
            "entry_type": "eval", "probe": "promptinject.Test", "detector": "promptinject.AttackRogueString",
            "passed": 2, "fails": 1, "total_processed": 3, "nones": 0,
        }) + "\n", encoding="utf-8")
        self.store.update(sid, status="complete", report_file=report.name)
        response = self.client.get(f"/scan/{sid}/report")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["component_name"], "Search")
        self.assertEqual(response.json()["mode"], "http")
        self.assertEqual(response.json()["methodology"]["result_type"], "automated_candidate_findings")

    def test_local_lab_endpoint_requires_startup_allowlist_and_loopback_client(self):
        from app import lab_policy
        endpoint = "http://127.0.0.1:3001/api/v1/workspace/arisec-lab/chat"
        lab_policy.configure_local_targets([endpoint])
        self.addCleanup(lab_policy.configure_local_targets, [])
        local = TestClient(main.app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 49100))
        with patch.dict(os.environ, {"ARISEC_LOCAL_DEMO": "1"}):
            response = local.post("/scan", json=self.body(target_url=endpoint))
        self.assertEqual(response.status_code, 202, response.text)
        remote = TestClient(main.app, client=("192.0.2.1", 49101))
        response = remote.post("/scan", json=self.body(target_url=endpoint))
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
