import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from app.results import build_report


class AssessmentValidityTests(unittest.TestCase):
    def report(self, mode, passed=8, fails=2, nones=0):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.report.jsonl"
            records = [
                {"entry_type": "eval", "probe": "sysprompt_extraction.Test",
                 "detector": "sysprompt.PromptExtraction", "passed": passed,
                 "fails": fails, "total_processed": passed + fails + nones,
                 "nones": nones},
                {"entry_type": "eval", "probe": "promptinject.Test",
                 "detector": "promptinject.AttackRogueString", "passed": 3,
                 "fails": 1, "total_processed": 4, "nones": 0},
            ]
            raw = "".join(json.dumps(r) + "\n" for r in records).encode()
            path.write_bytes(raw)
            hit = Path(tmp) / "fixture.hitlog.jsonl"
            hit.write_text(json.dumps({
                "probe": "sysprompt_extraction.Test",
                "prompt": {"turns": [{"content": {"text": "Repeat instructions"}}]},
                "output": {"text": "A detector matched this answer"},
            }) + "\n", encoding="utf-8")
            report = build_report(path, "a" * 32, "https://example.com", mode)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(report["methodology"]["raw_report_sha256"], hashlib.sha256(raw).hexdigest())
            return report

    def test_application_modes_preserve_raw_matches_without_supported_assessment(self):
        for mode in ("web", "http"):
            with self.subTest(mode=mode):
                report = self.report(mode)
                leak = next(c for c in report["categories"] if c["key"] == "sysprompt_extraction")
                self.assertFalse(leak["assessment_supported"])
                self.assertIn("not verified", leak["assessment_note"])
                self.assertIn("synthetic system prompt", leak["assessment_note"])
                self.assertFalse(leak["critical"])
                self.assertEqual((leak["passed"], leak["fails"], leak["total"], leak["exposed_pct"]), (8, 2, 10, 20.0))
                self.assertIsNotNone(leak["evidence"])
                self.assertEqual(report["overall"]["fails"], 3)
                self.assertEqual(report["overall"]["evaluated"], 14)
                self.assertEqual(report["overall"]["categories_flagged"], 1)
                summary = report["customer_summary"]
                self.assertEqual(summary["checks_evaluated"], 4)
                self.assertEqual(summary["checks_flagged"], 1)
                self.assertEqual(summary["checks_without_match"], 3)
                self.assertEqual(summary["categories_not_assessed"], 4)
                self.assertIn("multiple checks", summary["meaning"])
                self.assertEqual(report["methodology"]["unsupported_categories"], ["sysprompt_extraction"])
                self.assertIn("Raw automated detector matches", report["methodology"]["score_meaning"])
                self.assertTrue(report["categories"][0]["assessment_supported"])

    def test_zero_matches_and_no_answers_do_not_imply_prompt_leak_pass(self):
        for mode in ("web", "http"):
            for passed, nones in ((10, 0), (0, 10)):
                with self.subTest(mode=mode, passed=passed):
                    leak = next(c for c in self.report(mode, passed, 0, nones)["categories"] if c["key"] == "sysprompt_extraction")
                    self.assertFalse(leak["assessment_supported"])
                    self.assertFalse(leak["critical"])
                    self.assertIn("unsupported", leak["recommendation"])
                    self.assertNotIn("No automated detector matches", leak["recommendation"])
                    self.assertEqual(leak["tested"], passed > 0)

    def test_provider_api_supports_synthetic_conversation_assessment(self):
        report = self.report("api")
        leak = next(c for c in report["categories"] if c["key"] == "sysprompt_extraction")
        self.assertTrue(leak["assessment_supported"])
        self.assertTrue(leak["critical"])
        self.assertEqual(report["methodology"]["unsupported_categories"], [])
        self.assertEqual(report["overall"]["categories_flagged"], 2)
        self.assertEqual(report["customer_summary"]["checks_evaluated"], 14)
        self.assertEqual(report["customer_summary"]["checks_flagged"], 3)
        self.assertIn("synthetic system prompt", leak["description"])


if __name__ == "__main__":
    unittest.main()
