import json
import tempfile
import unittest
from pathlib import Path

from app.results import build_report


class ReportRecommendationsTests(unittest.TestCase):
    def report(self, passed, fails, nones=0):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "garak.test.report.jsonl"
            path.write_text(json.dumps({
                "entry_type": "eval", "probe": "promptinject.Test",
                "detector": "promptinject.AttackRogueString",
                "passed": passed, "fails": fails,
                "total_processed": passed + fails + nones, "nones": nones,
            }) + "\n", encoding="utf-8")
            return build_report(path, "a" * 32, "https://example.com")

    def test_failure_below_display_threshold_requires_remediation(self):
        category = self.report(19, 1)["categories"][0]
        self.assertEqual(category["exposed_pct"], 5.0)
        self.assertFalse(category["critical"])
        self.assertNotIn("No action needed", category["recommendation"])
        self.assertIn("instructions", category["recommendation"].lower())

    def test_untested_category_is_not_reassuring(self):
        category = self.report(20, 0)["categories"][1]
        self.assertFalse(category["tested"])
        self.assertIn("run this category again", category["recommendation"])

    def test_low_coverage_requests_repeat(self):
        category = self.report(1, 0, 9)["categories"][0]
        self.assertTrue(category["low_coverage"])
        self.assertIn("unanswered", category["recommendation"])

    def test_clean_sample_does_not_guarantee_security(self):
        self.assertIn("not a guarantee", self.report(20, 0)["categories"][0]["recommendation"])


if __name__ == "__main__":
    unittest.main()
